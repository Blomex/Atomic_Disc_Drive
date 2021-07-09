mod domain;

pub use crate::domain::*;
use crate::{MyRegisterClient, MAX_WORKERS};
pub use atomic_register_public::*;
use hmac::{Hmac, NewMac, Mac};
pub use register_client_public::*;
pub use sectors_manager_public::*;
use sha2::{Sha256};
pub use stable_storage_public::*;
use std::sync::{Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
pub use transfer_public::*;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use tokio::sync::Mutex;
use std::collections::{HashMap};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;


pub async fn run_register_process(config: Configuration) {
    //This is an asynchronous function, which must run your register and await for commands over TCP
    let hmac_client = config.hmac_client_key;
    let hmac_server = config.hmac_system_key;
    let storage_dir = config.public.storage_dir;
    let max_sector = config.public.max_sector;
    let process_rank = config.public.self_rank;
    // we are listening on our ip and port
    let tcp_locations = config.public.tcp_locations.clone();
    let (ip, port) = config.public.tcp_locations[(process_rank - 1) as usize].clone();
    let tcp_listener = TcpListener::bind((ip, port)).await;
    let mut busy = vec![];
    //create workers
    let mut workers: Vec<Arc<Mutex<Box<dyn AtomicRegister>>>> = Vec::new();
    let client_key = hmac_client.clone();
    let mac_server = HmacSha256::new_varkey(hmac_server.clone().as_ref()).unwrap();
    let register_client : Arc<MyRegisterClient> = Arc::new(MyRegisterClient {
        tcp_locations: config.public.tcp_locations.clone(),
        system_mac: mac_server.clone(),
        messages_to_send: Arc::new(Mutex::new(HashMap::new())),
    });
    for i in 0..MAX_WORKERS {
        let mut metadata_path = storage_dir.clone();
        metadata_path.push("metadata");
        metadata_path.push(i.to_string().as_str()); // workers have distinct stable storages
        let storage = Box::new(MyStableStorage {
            root_dir: metadata_path,
        });
        let (register, _command) = build_atomic_register(
            process_rank,
            storage,
            register_client.clone(),
            build_sectors_manager(storage_dir.clone()),
            config.public.tcp_locations.len(),
        )
        .await;
        workers.push(Arc::new(Mutex::new(register)));
        busy.push(Arc::new(tokio::sync::Semaphore::new(1)));
    }
    //spawn message sender every 500 ms
    let cloned_rc = register_client.clone();
    tokio::spawn(async move{
        cloned_rc.send_all_not_sent_messages().await;
    });

    loop {
        match &tcp_listener {
            Ok(listener) => {
                match listener.accept().await {
                    Ok((socket, _addr)) => {
                        //let mut arc_socket = Arc::new(Mutex::new(socket));
                        let cloned_tcp_locations = tcp_locations.clone();
                        let cmac = HmacSha256::new_varkey(client_key.clone().as_ref()).unwrap();
                        let smac = mac_server.clone();
                        let cloned_workers = workers.clone();
                        let busy_workers = busy.clone();
                        let cloned_register_client = register_client.clone();
                        tokio::spawn(async move {
                                let std_socket = socket.into_std().unwrap().try_clone().unwrap();
                                loop {
                                    let mut socket = TcpStream::from_std(std_socket.try_clone().unwrap()).unwrap();
                                    let mut std_socket = std_socket.try_clone().unwrap();
                                    let mut server_mac = smac.clone();
                                    let client_mac_closure = cmac.clone();
                                    let mut magic_buffer: Vec<u8> = vec![0; 4];
                                    let mut padding_and_type: Vec<u8> = vec![0; 4];
                                    // let mut guard = arc_socket.lock().await;
                                    // let socket = guard.deref_mut();
                                    let result = socket.read_exact(magic_buffer.as_mut()).await.is_ok();
                                    if !result {
                                        // drop(guard);
                                        return;
                                    }
                                    //sliding through bytes, until magic number is found
                                    while magic_buffer != MAGIC_NUMBER {
                                        let mut slider: [u8; 1] = [0];
                                        magic_buffer[0] = magic_buffer[1];
                                        magic_buffer[1] = magic_buffer[2];
                                        magic_buffer[2] = magic_buffer[3];
                                        let result = socket.read_exact(slider.as_mut()).await.is_ok();
                                        if !result {
                                            //    drop(guard);
                                            return;
                                        }
                                        magic_buffer[3] = slider[0];
                                    }
                                    //read message type
                                    if !socket.read_exact(padding_and_type.as_mut()).await.is_ok() {
                                        //  drop(guard);
                                        return;
                                    }
                                    //message type is under index 3, rest is padding or process rank
                                    let message_type = MessageType::from(padding_and_type[3]);
                                    let size_of_rest =
                                        get_recv_message_size(message_type);
                                    let size_of_hmac = 32;
                                    let mut rest_of_message: Vec<u8> = vec![0; size_of_rest];
                                    if !socket.read_exact(rest_of_message.as_mut()).await.is_ok() {
                                        // drop(guard);
                                        return;
                                    }
                                    // drop(guard);
                                    magic_buffer.extend_from_slice(padding_and_type.as_slice());
                                    magic_buffer.extend_from_slice(rest_of_message.as_slice());

                                    //check if hmac is correct
                                    let (message, hmac) =
                                        magic_buffer.split_at(8 + size_of_rest - size_of_hmac);
                                    let hmac_check = match message_type {
                                        MessageType::ClientRead | MessageType::ClientWrite => {
                                            let mut client_mac = HmacSha256::new_varkey(client_key.as_ref()).unwrap();
                                            client_mac.update(message.clone());
                                            client_mac.verify(hmac).is_ok()
                                        }
                                        MessageType::Value | MessageType::Ack
                                        | MessageType::WriteProc | MessageType::ReadProc | MessageType::ResponseServer => {
                                            server_mac.update(message.clone());
                                            server_mac.verify(hmac).is_ok()
                                        }
                                        _ => { false }
                                    };

                                    //if hmac is correct, delegate work to task
                                    {
                                        let cloned_tcp_locations = cloned_tcp_locations.clone();
                                        let cloned_workers = cloned_workers.clone();
                                        let busy_workers = busy_workers.clone();
                                        let cloned_register_client = cloned_register_client.clone();
                                        let server_mac = smac.clone();
                                    tokio::spawn(async move {
                                        if message_type == MessageType::ResponseServer {
                                            //  println!("got server response, modifying msg");
                                            let (start, _hmac) = magic_buffer.split_at(24);
                                            let (beggining, uuid_bytes) = start.split_at(8);
                                            let uuid = Uuid::from_slice(uuid_bytes).unwrap();
                                            let mut guard = cloned_register_client.messages_to_send.lock().await;
                                            let maybe_result = guard.get_mut(&uuid);
                                            match maybe_result{
                                                None => {}
                                                Some((recv_set, _)) => {
                                                  //  println!("removing {:} from confirmation list", beggining[6]);
                                                    let process_id = beggining[6] - 1; // remember that process is under index (rank-1)
                                                    // println!("process id: {:}", process_id);
                                                    if recv_set.contains(&process_id) {
                                                        recv_set.remove(&process_id);
                                                    }
                                                    if recv_set.len() == 0 {
                                                        guard.remove(&uuid).unwrap();
                                                        // msgs.remove(&uuid).unwrap();
                                                    }
                                                }
                                            }
                                        }
                                        let command = deserialize_register_command(&mut magic_buffer.deref());
                                        if hmac_check {
                                            match command {
                                                Ok(register_command) => {
                                                    let sector_idx = match &register_command {
                                                        RegisterCommand::Client(crc) => {
                                                            crc.header.sector_idx
                                                        }
                                                        RegisterCommand::System(src) => {
                                                            src.header.sector_idx
                                                        }
                                                    };
                                                   // println!("operation concerns sector{:?}", sector_idx);
                                                    //pass command
                                                    match register_command {
                                                        RegisterCommand::Client(crc) => {
                                                            //check if sector is correct, if not, return immediately
                                                            if sector_idx >= max_sector {
                                                                let op = OperationComplete {
                                                                    status_code: StatusCode::InvalidSectorIndex,
                                                                    request_identifier: crc.header.request_identifier,
                                                                    op_return: match crc.content {
                                                                        ClientRegisterCommandContent::Read => {
                                                                            OperationReturn::Read(ReadReturn { read_data: None })
                                                                        }
                                                                        ClientRegisterCommandContent::Write { .. } => {
                                                                            OperationReturn::Write
                                                                        }
                                                                    },
                                                                };
                                                                // println!("invalid sector index");
                                                                let response_bytes: Vec<u8> = serialize_response_message(op.clone(), client_mac_closure.clone(), crc.header.request_identifier.clone());
                                                                //let mut guard = arc_socket.lock().await;
                                                                //let socket = guard.deref_mut();
                                                                socket.write_all(response_bytes.as_slice()).await.ok();
                                                                //drop(guard);
                                                            }
                                                          //  println!("before mutex {}", sector_idx % MAX_WORKERS);
                                                            let semaphore = busy_workers.get((sector_idx % MAX_WORKERS) as usize).cloned().unwrap();
                                                            let _permit = semaphore.acquire_owned().await;
                                                          //  println!("trying to get mutex nr {:}", sector_idx % MAX_WORKERS);
                                                            let mutex = cloned_workers.get((sector_idx % MAX_WORKERS) as usize).cloned().unwrap();
                                                            let mut guard = mutex.lock().await;
                                                            let register = guard.deref_mut();
                                                            let request_id = crc.header.request_identifier;
                                                        //    println!("inside mutex {}", sector_idx % MAX_WORKERS);
                                                            //let cloned_arc_socket = arc_socket.clone();
                                                            // println!("creating callback");
                                                            let function = Box::new(move |operation_complete: OperationComplete| {
                                                                //  println!("callback called");
                                                                let response_bytes: Vec<u8> = serialize_response_message(operation_complete.clone(), client_mac_closure, request_id);
                                                                std_socket.write_all(response_bytes.as_slice()).ok();
                                                                drop(_permit);
                                                            });
                                                            register.client_command(crc, function).await;
                                                     //       println!("after mutex {}", sector_idx % MAX_WORKERS);
                                                        }
                                                        RegisterCommand::System(src) => {
                                                       //     println!("trying to get mutex nr {:}", sector_idx % MAX_WORKERS);
                                                            let mutex = cloned_workers.get((sector_idx % MAX_WORKERS) as usize).cloned().unwrap();
                                                        //    println!("inside mutex {:}", sector_idx % MAX_WORKERS);
                                                            let uuid = src.header.msg_ident.clone();
                                                            let response_receiver = src.header.process_identifier;
                                                            let mut guard = mutex.lock().await;
                                                            let register = guard.deref_mut();
                                                            register.system_command(src).await;
                                                            drop(guard);
                                                            //send acknowledgement to system
                                                            let mut acknowledgement: Vec<u8> = vec![];
                                                            acknowledgement.extend_from_slice(MAGIC_NUMBER.as_ref());
                                                            acknowledgement.extend_from_slice([0_u8, 0_u8, process_rank as u8, 0x81 as u8].as_ref());
                                                            acknowledgement.extend_from_slice(uuid.as_bytes());
                                                            let mut mac = server_mac.clone();
                                                            mac.update(&acknowledgement);
                                                            let mac_result = mac.finalize().into_bytes();
                                                            acknowledgement.extend_from_slice(mac_result.as_slice());

                                                            let addr = cloned_tcp_locations.get((response_receiver - 1) as usize).unwrap();
                                                            let stream = TcpStream::connect(addr).await;
                                                            match stream {
                                                                Ok(mut stream) => {
                                                                    // println!("sending acknowledgement");
                                                                    stream.write_all(acknowledgement.as_slice()).await.ok();
                                                                }
                                                                Err(err) => {
                                                                    log::debug!("err when sending confirmation: {:}", err);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    log::debug!("error: {:}", err);
                                                }
                                            }
                                        } else {
                                            match command {
                                                Ok(RegisterCommand::Client(crc)) => {
                                                    let op = OperationComplete {
                                                        status_code: StatusCode::AuthFailure,
                                                        request_identifier: crc.header.request_identifier,
                                                        op_return: match crc.content {
                                                            ClientRegisterCommandContent::Read => {
                                                                OperationReturn::Read(ReadReturn { read_data: None })
                                                            }
                                                            ClientRegisterCommandContent::Write { .. } => {
                                                                OperationReturn::Write
                                                            }
                                                        }
                                                    };
                                                    let op_bytes = serialize_response_message(op, client_mac_closure, crc.header.request_identifier);
                                                    //let mut guard = arc_socket.lock().await;
                                                    //let socket = guard.deref_mut();
                                                    socket.write_all(op_bytes.as_slice()).await.ok();
                                                    //drop(guard);
                                                }
                                                _ => {
                                                    //   println!("incorrect message received");
                                                }//ignore incorrect system command
                                            }
                                        }
                                    });
                                }
                                }

                            },
                        );
                    }
                    Err(e) => {
                        log::debug!("couldn't connect with client {:}", e);
                    }
                }
            }
            Err(e) => {
                log::debug!("couldn't create listener {:}", e);
            }
        }
    }
}

fn serialize_response_message(operation_complete: OperationComplete, mut mac:HmacSha256, request_id : u64) -> Vec<u8> {
    let mut bytes : Vec<u8> = Vec::new();
    bytes.extend_from_slice(MAGIC_NUMBER.clone().as_ref());
    let mut padding = vec![0; 4];

    padding[2] = operation_complete.status_code as u8;
    padding[3] = match &operation_complete.op_return{
        OperationReturn::Read(_) => {0x41}
        OperationReturn::Write => { 0x42 }
    };
    bytes.extend_from_slice(padding.as_slice());
    bytes.extend_from_slice(request_id.to_be_bytes().as_ref());
    if operation_complete.status_code == StatusCode::Ok {
        match &operation_complete.op_return {
            OperationReturn::Read(read_return) => bytes.extend_from_slice(read_return.read_data.as_ref().unwrap().0.as_slice()),
            _ => {}
        }
    }
    mac.update(bytes.as_slice());
    let result = mac.finalize().into_bytes();
    bytes.extend_from_slice(result.as_slice());
    bytes
}


pub mod atomic_register_public {
    use crate::{register_client_public, Broadcast, ClientRegisterCommand, ClientRegisterCommandContent, OperationComplete, OperationReturn, RegisterClient, SectorVec, SectorsManager, StableStorage, StatusCode, SystemCommandHeader, SystemRegisterCommand, SystemRegisterCommandContent, ReadReturn, ClientCommandHeader};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use uuid::Uuid;
    use std::convert::TryInto;
    use std::borrow::Borrow;

    pub(crate) struct MyAtomicRegister {
        //every register has hashmap for everything that needs to be unique to sector, where key is sector idx
        rank: u8,
        wr: HashMap<u64, u8>,
        ts: HashMap<u64, u64>,
        n : usize,
        initialized : HashSet<u64>,
        rid: HashMap<u64, u64>,
        write_val: HashMap<u64, SectorVec>,
        val : HashMap<u64, SectorVec>,
        read_val : HashMap<u64, SectorVec>,
        ack_list: HashMap<u64, HashSet<u8>>,
        read_list: HashMap<u64, HashMap<u8, (u64, u8, SectorVec)>>,
        writing: HashMap<u64, bool>,
        reading: HashMap<u64, bool>,
        store: Box<dyn StableStorage>,
        sbeb: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        operation_complete: HashMap<u64, Option<Box<dyn FnOnce(OperationComplete) + Send + Sync>>>,
    }
    impl MyAtomicRegister{
        fn serialize_client_message(&self, data: &ClientRegisterCommand) -> Vec<u8>{
            let mut bytes : Vec<u8> = Vec::new();
            bytes.extend_from_slice(data.header.sector_idx.to_be_bytes().as_ref());
            bytes.extend_from_slice(data.header.request_identifier.to_be_bytes().as_ref());
            match data.content.clone(){
                ClientRegisterCommandContent::Read => {
                }
                ClientRegisterCommandContent::Write { data } => {
                    bytes.extend_from_slice(data.0.as_slice())
                }
            }
            bytes
        }
        fn deserialize_client_message(&self, bytes: &Vec<u8>) -> ClientRegisterCommand{
            let (sector_bytes, rest) = bytes.split_at(8);
            let (request_bytes, rest) = rest.split_at(8);
            let sector_idx = u64::from_be_bytes(sector_bytes.try_into().unwrap());
            let request_id = u64::from_be_bytes(request_bytes.try_into().unwrap());
            if rest.len() > 0{
                let writeval_bytes = SectorVec(Vec::from(rest));
                return ClientRegisterCommand{
                    header: ClientCommandHeader{
                        request_identifier: request_id,
                        sector_idx
                    },
                    content: ClientRegisterCommandContent::Write {
                        data: writeval_bytes,
                    }
                }
            }
            ClientRegisterCommand{
                header: ClientCommandHeader{
                    request_identifier: request_id,
                    sector_idx
                },
                content: ClientRegisterCommandContent::Read,
            }
        }

        fn serialize_u64_u64_map(&self, data: &HashMap<u64, u64>) -> Vec<u8>{
            let mut vec : Vec<u8> = Vec::with_capacity(16*data.len());
            for(k, v) in data{
                vec.extend_from_slice(k.to_be_bytes().as_ref());
                vec.extend_from_slice(v.to_be_bytes().as_ref());
            }
            vec
        }
        fn serialize_u64_bool_map(&self, data: &HashMap<u64, bool>) -> Vec<u8>{
            let mut vec : Vec<u8> = Vec::with_capacity(data.len()*9);
            for (k, v) in data{
                vec.extend_from_slice(k.to_be_bytes().as_ref());
                vec.push(v.clone() as u8);
            }
            vec
        }
        fn serialize_u64_hashset(&self, data: &HashSet<u64>) -> Vec<u8>{
            let mut vec : Vec<u8> =  Vec::with_capacity(data.len() *8);
            for item in data{
                vec.extend_from_slice(item.to_be_bytes().as_ref());
            }
            vec
        }
        fn deserialize_u64_hashset(&self, data: &Vec<u8>) -> HashSet<u64>{
            let chunks = data.chunks_exact(8);
            let mut result = HashSet::new();
            for chunk in chunks{
                result.insert(u64::from_be_bytes(chunk.try_into().unwrap()));
            }
            result
        }
        fn deserialize_u64_u64_map(&self, data: &Vec<u8>) -> HashMap<u64, u64>{
            let chunks = data.chunks_exact(16);
            let mut result = HashMap::new();
            for chunk in chunks{
                let(sector_bytes, value_bytes) = chunk.split_at(8);
                let sector_idx = u64::from_be_bytes(sector_bytes.try_into().unwrap());
                let value = u64::from_be_bytes(value_bytes.try_into().unwrap());
                result.insert(sector_idx, value);
            }
            result
        }
        fn deserialize_u64_bool_map(&self, data:&Vec<u8>) -> HashMap<u64, bool>{
            let chunks = data.chunks_exact(9);
            let mut result = HashMap::new();
            for chunk in chunks {
                let (u64_bytes, u8_byte) = chunk.split_at(8);
                let sector_idx = u64::from_be_bytes(u64_bytes.try_into().unwrap());
                result.insert(sector_idx, u8_byte[0] != 0);
            }
            result
        }
        fn serialize_write_val(&self, data:&(u64, u8, SectorVec)) -> Vec<u8>{
            let mut bytes : Vec<u8> = vec![];
            bytes.extend_from_slice(data.0.to_be_bytes().as_ref());
            bytes.push(data.1);
            bytes.extend_from_slice(data.2.0.as_slice());
            bytes

        }
        fn deserialize_write_val(&self, data: &Vec<u8>) -> (u64, u8, SectorVec){
            let (u64_bytes, rest) = data.split_at(8);
            let (u8_bytes, sectorvecbytes) = rest.split_at(1);
            (u64::from_be_bytes(u64_bytes.try_into().unwrap()), u8_bytes[0], SectorVec(Vec::from(sectorvecbytes)))
        }

        async fn init_sector(&mut self, sector : u64){
            if !self.initialized.contains(&sector){
                //acts as 'init' for sectors that was not visited previously
                //initialize
                self.initialized.insert(sector);
                //ts, wr, val
                self.ts.insert(sector, 0);
                self.wr.insert(sector, 0);
                self.val.insert(sector, SectorVec(vec![0_u8; 4096]));
                self.rid.insert(sector, 0);

                self.read_list.insert(sector, HashMap::new());
                self.ack_list.insert(sector, HashSet::new());

                self.reading.insert(sector, false);
                self.writing.insert(sector, false);

                self.write_val.insert(sector, SectorVec(vec![0_u8; 4096]));
                self.read_val.insert(sector, SectorVec(vec![0_u8; 4096]));

                //if stable storage fails to save some data we cannot do anything about this anyway
                //store(wr, ts, val)
                self.sectors_manager.write(sector, &(SectorVec(vec![0_u8; 4096]), 0 as u64, 0 as u8)).await;
                //store(rid)
                let rid_bytes = self.serialize_u64_u64_map(&self.rid);
                self.store.put("rid", rid_bytes.as_slice()).await.ok();
                //store(writing)
                let writing_bytes = self.serialize_u64_bool_map(&self.writing);
                self.store.put("writing", writing_bytes.as_slice()).await.ok();
                //store writeval
                let writeval_bytes = self.serialize_write_val(&(0 as u64, 0 as u8, SectorVec(vec![0_u8 ;4096])));
                self.store.put(&("writeval".to_owned() + sector.to_string().as_str()), writeval_bytes.as_slice()).await.ok();
                //store initialized set of sectors
                let initialized_bytes = self.serialize_u64_hashset(&self.initialized);
                self.store.put("initialized",initialized_bytes.as_slice()).await.ok();
            }
        }
    }

    #[async_trait::async_trait]
    impl AtomicRegister for MyAtomicRegister {
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            operation_complete: Box<dyn FnOnce(OperationComplete) + Send + Sync>,
        ) {
            // init if not initialized
            self.init_sector(cmd.header.sector_idx).await;

            let serialized_cmd = self.serialize_client_message(cmd.borrow());
            self.store.put("client_command", serialized_cmd.as_slice()).await.ok();

            self.operation_complete.insert(cmd.header.sector_idx, Some(operation_complete));
            let sector = cmd.header.sector_idx;
            match cmd.content {
                //upon event < nnar, Read > do
                ClientRegisterCommandContent::Read => {
                    //rid = rid + 1;
                    self.rid.insert(sector, 1+self.rid.get(&sector).unwrap());
                    // store(rid)
                    let rid_bytes = self.serialize_u64_u64_map(&self.rid);
                    self.store.put("rid", rid_bytes.as_slice()).await.ok();

                    self.read_list.clear();
                    self.ack_list.clear();
                    self.reading.insert(sector, true);
                    //trigger < sbeb, Broadcast | [READ_PROC, rid] >;
                    self.sbeb
                        .broadcast(Broadcast {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.rank,
                                    msg_ident: Uuid::new_v4(),
                                    read_ident: self.rid.get(&sector).unwrap().clone(),
                                    sector_idx: sector,
                                },
                                content: SystemRegisterCommandContent::ReadProc,
                            }),
                        })
                        .await
                }
                //upon event < nnar, Write | v > do
                ClientRegisterCommandContent::Write { data } => {
                    self.rid.insert(sector, 1+self.rid.get(&sector).unwrap());

                    self.write_val.insert(sector, data);
                    self.ack_list.insert(sector, HashSet::new());
                    self.read_list.insert(sector, HashMap::new());
                    self.writing.insert(sector, true);


                    // store(wr, ts, rid, writeval, writing);

                    // store rid
                    let rid_bytes = self.serialize_u64_u64_map(&self.rid);
                    self.store.put("rid", rid_bytes.as_slice()).await.ok();
                    //store writeval
                    let wr = self.wr.get(&sector).unwrap();
                    let ts = self.ts.get(&sector).unwrap();
                    let writeval_bytes = self.serialize_write_val(&(ts.clone(), wr.clone(), self.write_val.get(&sector).unwrap().clone()));
                    self.store.put(&("writeval".to_owned() + sector.to_string().as_str()), writeval_bytes.as_slice()).await.ok();
                    //store writing
                    let writing_bytes = self.serialize_u64_bool_map((&self.writing));
                    self.store.put("writing", writing_bytes.as_slice()).await.ok();



                    //trigger <sbeb, Broadcast, | [READ_PROC, rid] > ;
                    self.sbeb
                        .broadcast(Broadcast {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.rank,
                                    msg_ident: Uuid::new_v4(),
                                    read_ident: self.rid.get(&sector).unwrap().clone(),
                                    sector_idx: sector,
                                },
                                content: SystemRegisterCommandContent::ReadProc,
                            }),
                        })
                        .await;
                }
            }
        }

        async fn system_command(&mut self, cmd: SystemRegisterCommand) {
            let r = cmd.header.read_ident;
            let q = cmd.header.process_identifier;
            let sector = cmd.header.sector_idx;
            self.init_sector(sector).await;

            match cmd.content {
                //upon event < sbeb, Deliver | p [READ_PROC, r] > do
                SystemRegisterCommandContent::ReadProc => {
                    //trigger < pl, Send | p, [VALUE, r, ts, wr, val] >;
                    self.sbeb
                        .send(register_client_public::Send {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.rank,
                                    msg_ident: Uuid::new_v4(),
                                    read_ident: cmd.header.read_ident,
                                    sector_idx: sector,
                                },
                                content: SystemRegisterCommandContent::Value {
                                    timestamp: self.ts.get(&sector).unwrap().clone(),
                                    write_rank: self.wr.get(&sector).unwrap().clone(),
                                    sector_data: self.val.get(&sector).unwrap().clone(),
                                },
                            }),
                            target: cmd.header.process_identifier as usize,
                        })
                        .await;
                }
                //upon event <sl, Deliver | q, [VALUE, r, ts', wr', v'] > such that r == rid do
                SystemRegisterCommandContent::Value {
                    timestamp,
                    write_rank,
                    sector_data,
                } => {
                    if r == self.rid.get(&sector).unwrap().clone() {
                        //readlist[q] := (ts', wr', v');
                        if !self.read_list.contains_key(&sector) {
                            self.read_list.insert(sector, HashMap::new());
                        }
                        let readlist = self.read_list.get_mut(&sector).unwrap();
                        readlist.insert(q, (timestamp, write_rank, sector_data));
                        //if #(readlist) > N / 2 and (reading or writing) then
                        if readlist.len() > (self.n / 2)
                            && (self.reading.get(&sector).unwrap().clone()
                            || self.writing.get(&sector).unwrap().clone())
                        {
                            let mut max_ts = 0;
                            let mut rr = 0;
                            //(maxts, rr, readval) := highest(readlist);
                            for (_k, (curr_ts, curr_r, curr_readval)) in self.read_list.get(&sector).unwrap() {
                                if curr_ts.clone() > max_ts || (curr_ts.clone() == max_ts && curr_r.clone() >= rr) {
                                    max_ts = curr_ts.clone();
                                    rr = curr_r.clone();
                                    self.read_val.insert(sector, curr_readval.clone());
                                }
                            }

                            //readlist := [ _ ]
                            self.read_list.insert(sector, HashMap::new());
                            //acklist := [ _ ]
                            self.ack_list.insert(sector, HashSet::new());

                            //rid+=1, store rid

                            self.rid.insert(sector, 1+self.rid.get(&sector).unwrap().clone());
                            let rid_bytes = self.serialize_u64_u64_map(&self.rid);
                            self.store.put("rid", rid_bytes.as_slice()).await.ok();

                            if self.reading.get(&sector).unwrap().clone() {
                              //println!("process {:} triggers BROADCAST [WRITE_PROC]", self.rank);
                                self.sbeb
                                    .broadcast(Broadcast {
                                        cmd: Arc::new(SystemRegisterCommand {
                                            header: SystemCommandHeader {
                                                process_identifier: self.rank,
                                                msg_ident: Uuid::new_v4(),
                                                read_ident: self.rid.get(&sector).unwrap().clone(),
                                                sector_idx: cmd.header.sector_idx,
                                            },
                                            content: SystemRegisterCommandContent::WriteProc {
                                                timestamp: max_ts,
                                                write_rank: rr,
                                                data_to_write: self.read_val.get(&sector).unwrap().clone(),
                                            },
                                        }),
                                    })
                                    .await;
                            } else {
                                //writing
                                let writeval = self.write_val.get(&sector).unwrap().clone();
                            //    println!("process {:} triggers BROADCAST [WRITE_PROC]", self.rank);
                                self.sbeb
                                    .broadcast(Broadcast {
                                        cmd: Arc::new(SystemRegisterCommand {
                                            header: SystemCommandHeader {
                                                process_identifier: self.rank,
                                                msg_ident: Uuid::new_v4(),
                                                read_ident: self.rid.get(&sector).unwrap().clone(),
                                                sector_idx: cmd.header.sector_idx,
                                            },
                                            content: SystemRegisterCommandContent::WriteProc {
                                                timestamp: max_ts + 1,
                                                write_rank: self.rank,
                                                data_to_write: writeval,
                                            },
                                        }),
                                    })
                                    .await;
                            }
                        }
                    }
                }
                SystemRegisterCommandContent::WriteProc {
                    //upon event < sbeb, Deliver | p, [WRITE_PROC, r, ts', wr', v'] > do
                    timestamp,
                    write_rank,
                    data_to_write,
                } => {
                    //if (ts', wr') > (ts, wr) then
                    if timestamp > self.ts.get(&sector).unwrap().clone()
                        || (timestamp == self.ts.get(&sector).unwrap().clone()
                        && write_rank >= self.wr.get(&sector).unwrap().clone()) {
                        //(ts, wr, val) := (ts', wr', v');
                        self.ts.insert(sector, timestamp);
                        self.wr.insert(sector, write_rank);
                        self.val.insert(sector, data_to_write.clone());
                        // store(ts, wr, val);
                        self.sectors_manager.write(sector, &(data_to_write, timestamp, write_rank)).await;
                    }
                    //trigger < pl, Send | p, [ACK, r] >;
                    self.sbeb
                        .send(register_client_public::Send {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.rank,
                                    msg_ident: Uuid::new_v4(),
                                    read_ident: r,
                                    sector_idx: cmd.header.sector_idx,
                                },
                                content: SystemRegisterCommandContent::Ack,
                            }),
                            target: cmd.header.process_identifier as usize,
                        })
                        .await;
                }
                SystemRegisterCommandContent::Ack => {
                    //upon event < pl, Deliver | q, [ACK, r] > such that r == rid do
                    if self.rid.get(&sector).unwrap().clone() == cmd.header.read_ident {
                        //acklist[q] = Ack;
                        if !self.ack_list.contains_key(&sector){
                            self.ack_list.insert(sector, HashSet::new());
                        }
                        let acklist = self.ack_list.get_mut(&sector).unwrap();
                        acklist.insert(cmd.header.process_identifier);
                        if acklist.len().clone() > (self.n/ 2)
                            && (self.reading.get(&sector).unwrap().clone() || self.writing.get(&sector).unwrap().clone()) {
                            self.ack_list.insert(sector, HashSet::new());
                            if self.reading.get(&sector).unwrap().clone() {
                                self.reading.insert(sector, false);
                                // trigger < nnar, ReadReturn | readval >;
                                let read_data = self.read_val.get(&sector).cloned();
                                let maybe_callback = self.operation_complete.get_mut(&sector);
                                match maybe_callback {
                                    None => {}
                                    Some(callback) => {
                                        let callback = callback.take().unwrap();
                                        callback(OperationComplete{
                                            status_code: StatusCode::Ok,
                                            request_identifier: self.rid.get(&sector).unwrap().clone(),
                                            op_return: OperationReturn::Read(ReadReturn{ read_data }),
                                        })
                                    }
                                }
                                
                                
                            } else {
                                self.writing.insert(sector, false);
                                //store writing
                                let writing_bytes = self.serialize_u64_bool_map(&self.writing);
                                self.store.put("writing", writing_bytes.as_slice()).await.ok();
                                let maybe_callback = self.operation_complete.get_mut(&sector);
                                match maybe_callback {
                                    None => {}
                                    Some(callback) => {
                                        let callback = callback.take().unwrap();
                                        (callback)(OperationComplete{
                                            status_code: StatusCode::Ok,
                                            request_identifier: self.rid.get(&sector).unwrap().clone(),
                                            op_return: OperationReturn::Write
                                        })
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #[async_trait::async_trait]
    pub trait AtomicRegister: std::marker::Send {
        /// Send client command to the register. After it is completed, we expect
        /// callback to be called. Note that completion of client command happens after
        /// delivery of multiple system commands to the register, as the algorithm specifies.
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            operation_complete: Box<dyn FnOnce(OperationComplete) + Send + Sync>,
        );

        /// Send system command to the register.
        async fn system_command(&mut self, cmd: SystemRegisterCommand);
    }

    /// Idents are numbered starting at 1 (up to the number of processes in the system).
    /// Storage for atomic register algorithm data is separated into StableStorage.
    /// Communication with other processes of the system is to be done by register_client.
    /// And sectors must be stored in the sectors_manager instance.
    pub async fn build_atomic_register(
        self_ident: u8,
        metadata: Box<dyn StableStorage>,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: usize,
    ) -> (Box<dyn AtomicRegister>, Option<ClientRegisterCommand>) {
        let (mut temp_register, mut temp_command) =
        (
            Box::new(MyAtomicRegister {
                rank: self_ident,
                wr: HashMap::new(),
                ts: HashMap::new(),
                n: processes_count,
                initialized: HashSet::new(),
                rid: HashMap::new(),
                write_val: HashMap::new(),
                val: HashMap::new(),
                read_val: HashMap::new(),
                ack_list: HashMap::new(),
                read_list: HashMap::new(),
                writing: HashMap::new(),
                reading: HashMap::new(),
                store: metadata,
                sectors_manager,
                sbeb: register_client,
                operation_complete: HashMap::new(),
            }),
            None,
        );

        //retrieve already initialized
        let initialized_bytes = temp_register.store.get("initialized").await.unwrap_or(vec![]);
        temp_register.initialized = temp_register.deserialize_u64_hashset(initialized_bytes.as_ref());
        //retrieve 'writing'
        let writing_bytes = temp_register.store.get("writing").await.unwrap_or(vec![]);
        temp_register.writing = temp_register.deserialize_u64_bool_map(writing_bytes.as_ref());
        //retrieve wr
        let rid_bytes = temp_register.store.get("rid").await.unwrap_or(vec![]);
        temp_register.rid = temp_register.deserialize_u64_u64_map(rid_bytes.as_ref());


        //retrieve (wr, ts, val, writeval)
        for sector in temp_register.initialized.clone() {
            let val = temp_register.sectors_manager.read_data(sector).await;

            let writeval_bytes =  temp_register.store.get(&("writeval".to_owned() + sector.to_string().as_str())).await.unwrap_or(vec![]);
            let(_ts, _wr, write_val) = temp_register.deserialize_write_val(writeval_bytes.as_ref());
            let (ts, wr) = temp_register.sectors_manager.read_metadata(sector).await;
            temp_register.val.insert(sector, val.clone());
            temp_register.ts.insert(sector, ts);
            temp_register.wr.insert(sector, wr);
            //readlist, accklist, reading, readval
            temp_register.read_list.insert(sector, HashMap::new());
            temp_register.ack_list.insert(sector, HashSet::new());
            temp_register.reading.insert(sector, false);
            temp_register.read_val.insert(sector, SectorVec(vec![0; 4096]));
            //if writing then broadcast READ_PROC
            if temp_register.writing.get(&sector).unwrap().clone() {
                temp_register.write_val.insert(sector, write_val);
                temp_register.system_command(SystemRegisterCommand{
                    header: SystemCommandHeader {
                        process_identifier: temp_register.rank,
                        msg_ident: Uuid::new_v4(),
                        read_ident: temp_register.rid.get(&sector).unwrap().clone(),
                        sector_idx: sector
                    },
                    content: SystemRegisterCommandContent::ReadProc,
                }).await;
            }
        }
        //retrieve client command
        let cmd_bytes = temp_register.store.get("client_command").await;
        match cmd_bytes{
            None => {}
            Some(bytes) => {
                temp_command = Some(temp_register.deserialize_client_message(bytes.as_ref()));
            }
        }
        return (temp_register, temp_command)
    }
}

pub mod sectors_manager_public {
    use crate::{ SectorIdx, SectorVec};
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt};

    struct MySectorManager {
        base_path: PathBuf,
    }
    impl MySectorManager {
        fn serialize_metadata(&self, metadata: &HashMap<u64, (u64, u8)>) -> Option<Vec<u8>> {
            let mut byte_vector: Vec<u8> = vec![];

            for (k, (ts, wr)) in metadata {
                byte_vector.extend_from_slice(u64::to_be_bytes(k.clone()).as_ref());
                byte_vector.extend_from_slice(u64::to_be_bytes(ts.clone()).as_ref());
                byte_vector.push(wr.clone());
            }
            Some(byte_vector)
        }
        fn deserialize_metadata(&self, byte_vector: &Vec<u8>) -> HashMap<u64, (u64, u8)> {
            let mut metadata = HashMap::new();
            let chunks = byte_vector.chunks_exact(17);
            for chunk in chunks {
                let (idx_bytex, rest) = chunk.split_at(8);
                let (ts_bytes, wr) = rest.split_at(8);
                let sector_index = u64::from_be_bytes(idx_bytex.try_into().unwrap());
                let ts = u64::from_be_bytes(ts_bytes.try_into().unwrap());
                let wr = wr[0];
                metadata.insert(sector_index, (ts, wr));
            }
            metadata
        }
    }

    #[async_trait::async_trait]
    impl SectorsManager for MySectorManager {
        async fn read_data(&self, idx: u64) -> SectorVec {
            //first, we need path to directory with sector.
            let mut cloned_path = self.base_path.clone();
            cloned_path.push((idx % MAX_WORKERS).to_string());
            cloned_path.push(((idx / MAX_WORKERS) % MAX_WORKERS).to_string());
            //finally, append to path idx of sector to get correct file
            cloned_path.push(idx.to_string());
            match tokio::fs::read(cloned_path).await {
                Ok(bytes) => SectorVec(bytes),
                Err(_err) => {
                    let empty_data: Vec<u8> = vec![0; PAGE_SIZE];
                    SectorVec(empty_data)
                }
            }
        }

        async fn read_metadata(&self, idx: u64) -> (u64, u8) {
            //first, we need path to directory with sector.
            let mut cloned_path = self.base_path.clone();
            cloned_path.push((idx % MAX_WORKERS).to_string());
            cloned_path.push(((idx / MAX_WORKERS) % MAX_WORKERS).to_string());
            //metadata file
            cloned_path.push("metadata");
            return match tokio::fs::read(cloned_path).await {
                Ok(bytes) => {
                    let hashmap = self.deserialize_metadata(&bytes);
                    match hashmap.get(&idx) {
                        None => (0, 0),
                        Some(pair) => pair.clone(),
                    }
                }
                Err(_) => (0, 0),
            };
        }

        async fn write(&self, idx: u64, sector: &(SectorVec, u64, u8)) {
            let (data, ts, wr) = sector;
            //first, we need path to directory with sector.
            let mut cloned_path = self.base_path.clone();
            cloned_path.push((idx % MAX_WORKERS).to_string());
            cloned_path.push(((idx / MAX_WORKERS) % MAX_WORKERS).to_string());
            //finally, append to path idx of sector to get correct file
            let dir_path = cloned_path.clone();
            //first, make sure dir exists
            cloned_path.push(idx.to_string());
            // modify tmp metadata
            let mut metadata_tmp = dir_path.clone();
            let mut metadata_path = dir_path.clone();
            tokio::fs::create_dir_all(dir_path.clone()).await.unwrap();
            metadata_tmp.push("metadata_tmp");
            metadata_path.push("metadata");
            match tokio::fs::read(metadata_path.clone()).await {
                Ok(bytes) => {
                    let mut hashmap = self.deserialize_metadata(bytes.as_ref());
                    hashmap.insert(idx, (ts.clone(), wr.clone()));
                    let new_bytes = self.serialize_metadata(&hashmap).unwrap();
                    tokio::fs::write(metadata_tmp.clone(), new_bytes.as_slice()).await.unwrap();
                }
                Err(_) => {
                    let mut new_hashmap = HashMap::new();
                    new_hashmap.insert(idx, (ts.clone(), wr.clone()));
                    let new_bytes = self.serialize_metadata(&new_hashmap).unwrap();
                    tokio::fs::write(metadata_tmp.clone(), new_bytes.as_slice()).await.unwrap();
                }
            }
            //write to tmp file
            let mut file_tmp_path = dir_path.clone();
            file_tmp_path.push("tmp".to_owned() + idx.to_string().as_str());
            let mut file = tokio::fs::File::create(file_tmp_path.clone())
                .await
                .unwrap();
            file.write_all(data.0.as_slice()).await.unwrap();
            file.sync_all().await.unwrap();
            //rename file
            tokio::fs::rename(file_tmp_path, cloned_path)
                .await
                .unwrap();
            //rename metadata file
            tokio::fs::rename(metadata_tmp, metadata_path).await.unwrap();


            // tokio::fs::File::open(dir_path)
            //     .await
            //     .unwrap()
            //     .sync_data()
            //     .await
            //     .unwrap();
        }
    }

    #[async_trait::async_trait]
    pub trait SectorsManager: Send + Sync {
        /// Returns 4096 bytes of sector data by index.
        async fn read_data(&self, idx: SectorIdx) -> SectorVec;

        /// Returns timestamp and write rank of the process which has saved this data.
        /// Timestamps and ranks are relevant for atomic register algorithm, and are described
        /// there.
        async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8);

        /// Writes a new data, along with timestamp and write rank to some sector.
        async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8));
    }
    const PAGE_SIZE: usize = 4096;
    pub(crate) const MAX_WORKERS: u64 = 256;
    /// Path parameter points to a directory to which this method has exclusive access.
    pub fn build_sectors_manager(path: PathBuf) -> Arc<dyn SectorsManager> {
        Arc::new(MySectorManager { base_path: path })
    }
}

/// Your internal representation of RegisterCommand for ser/de can be anything you want,
/// we just would like some hooks into your solution to asses where the problem is, should
/// there be a problem.
pub mod transfer_public {
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub enum MessageType {
        None,
        ClientRead,
        ClientWrite,
        ReadProc,
        Value,
        WriteProc,
        Ack,
        ResponseClientRead = 0x41,
        ResponseClientWrite,
        ResponseReadProc,
        ResponseValue,
        ResponseWriteProc,
        ResponseAck,
        ResponseServer = 0x81,
    }

    /// returns size of message of given type
    /// size does not include first 8 bytes of the message (magic number and type)
    /// size does include hmac
    /// returns correct values only for message types, that are possible to receive by server
    pub fn get_recv_message_size(msg_type: MessageType) -> usize {
        match msg_type {
            MessageType::None => 0,
            MessageType::ClientRead => 48,
            MessageType::ClientWrite => 48 + 4096,
            MessageType::ReadProc => 64,
            MessageType::Value => 80 + 4096,
            MessageType::WriteProc => 80 + 4096,
            MessageType::Ack => 64,
            MessageType::ResponseServer => 48,
            _ => 0,
        }
    }
    #[derive(Debug, Clone)]
    pub enum Command {
        Register(RegisterCommand),
        Response(OperationComplete),
    }

    impl From<u8> for MessageType {
        fn from(value: u8) -> Self {
            match value {
                x if x == MessageType::Ack as u8 => MessageType::Ack,
                x if x == MessageType::WriteProc as u8 => MessageType::WriteProc,
                x if x == MessageType::ReadProc as u8 => MessageType::ReadProc,
                x if x == MessageType::ClientWrite as u8 => MessageType::ClientWrite,
                x if x == MessageType::ClientRead as u8 => MessageType::ClientRead,
                x if x == MessageType::Value as u8 => MessageType::Value,
                x if x == MessageType::ResponseAck as u8 => MessageType::ResponseAck,
                x if x == MessageType::ResponseClientRead as u8 => MessageType::ResponseClientRead,
                x if x == MessageType::ResponseClientWrite as u8 => {
                    MessageType::ResponseClientWrite
                }
                x if x == MessageType::ResponseReadProc as u8 => MessageType::ResponseReadProc,
                x if x == MessageType::ResponseValue as u8 => MessageType::ResponseValue,
                x if x == MessageType::ResponseWriteProc as u8 => MessageType::ResponseWriteProc,
                x if x == MessageType::ResponseServer as u8 => MessageType::ResponseServer,
                _ => MessageType::None,
            }
        }
    }
    use crate::{
        ClientCommandHeader, ClientRegisterCommand, ClientRegisterCommandContent,
        OperationComplete, RegisterCommand, SectorVec, SystemCommandHeader, SystemRegisterCommand,
        SystemRegisterCommandContent, MAGIC_NUMBER,
    };
    use std::convert::{TryInto};
    use std::io::{Error, Read, Write, ErrorKind};
    use uuid::Uuid;

    pub fn deserialize_register_command(data: &mut dyn Read) -> Result<RegisterCommand, Error> {
        let mut magic_buffer: [u8; 4] = [0, 0, 0, 0];
        let page_size: usize = 4096;
        data.read_exact(magic_buffer.as_mut())?;
        while magic_buffer != MAGIC_NUMBER {
            let mut slider: [u8; 1] = [0];
            magic_buffer[0] = magic_buffer[1];
            magic_buffer[1] = magic_buffer[2];
            magic_buffer[2] = magic_buffer[3];
            data.read_exact(slider.as_mut())?;
            magic_buffer[3] = slider[0];
        }
        //magic number is correct now
        let mut message_type: [u8; 4] = Default::default();
        data.read_exact(message_type.as_mut())?;
        //There is some padding, message type is 4th byte
        let mut register_command: RegisterCommand =
            RegisterCommand::Client(ClientRegisterCommand::default());
        match MessageType::from(message_type[3]) {
            MessageType::None => {}
            MessageType::ClientRead => {
                //rest of read message has 16 bytes
                let mut rest_of_message: Vec<u8> = vec![0; 16];
                data.read_exact(rest_of_message.as_mut())?;
                let (req_bytes, rest) = rest_of_message.split_at(std::mem::size_of::<u64>());
                let request_number: u64 = u64::from_be_bytes(req_bytes.try_into().unwrap());
                let (sec_bytes, _rest) = rest.split_at(std::mem::size_of::<u64>());
                let sector_index: u64 = u64::from_be_bytes(sec_bytes.try_into().unwrap());
                register_command = RegisterCommand::Client(ClientRegisterCommand {
                    header: ClientCommandHeader {
                        request_identifier: request_number,
                        sector_idx: sector_index,
                    },
                    content: ClientRegisterCommandContent::Read,
                });
            }
            MessageType::ClientWrite => {
                //rest of client write message has (16 + 4096) bytes
                let mut rest_of_message: Vec<u8> = vec![0; page_size + 16];
                data.read_exact(rest_of_message.as_mut())?;
                let (req_bytes, rest) = rest_of_message.split_at(std::mem::size_of::<u64>());
                let request_number: u64 = u64::from_be_bytes(req_bytes.try_into().unwrap());
                let (sector_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                let sector_index = u64::from_be_bytes(sector_bytes.try_into().unwrap());
                let (content, _hmac) = rest.split_at(page_size);
                register_command = RegisterCommand::Client(ClientRegisterCommand {
                    header: ClientCommandHeader {
                        request_identifier: request_number,
                        sector_idx: sector_index,
                    },
                    content: ClientRegisterCommandContent::Write {
                        data: SectorVec(Vec::from(content)),
                    },
                });
            }
            MessageType::ReadProc => {
                //READ_PROC has 8+(32) bytes
                let mut rest_of_message: Vec<u8> = vec![0; 32];
                data.read_exact(rest_of_message.as_mut())?;
                //Uuid
                let (uuid_bytes, rest) = rest_of_message.split_at(16);
                //read ident
                let (rid_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                //sector idx
                let (sec_bytes, _rest) = rest.split_at(std::mem::size_of::<u64>());
                //process rank is in message_type[2], one byte before actual msg type
                register_command = RegisterCommand::System(SystemRegisterCommand {
                    header: SystemCommandHeader {
                        process_identifier: message_type[2],
                        msg_ident: Uuid::from_bytes(uuid_bytes.try_into().unwrap()),
                        read_ident: u64::from_be_bytes(rid_bytes.try_into().unwrap()),
                        sector_idx: u64::from_be_bytes(sec_bytes.try_into().unwrap()),
                    },
                    content: SystemRegisterCommandContent::ReadProc,
                })
            }
            MessageType::Value => {
                //Value has 8 + (32 + 16 + 4096) bytes
                let mut rest_of_message: Vec<u8> = vec![0; 48 + page_size];
                data.read_exact(rest_of_message.as_mut())?;
                //Uuid
                let (uuid_bytes, rest) = rest_of_message.split_at(16);
                //read ident
                let (rid_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                //sector idx
                let (sec_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                //timestamp
                let (ts_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                let (_padding, rest) = rest.split_at(7);
                let (value_wr, rest) = rest.split_at(1);
                let (sector_data, _rest) = rest.split_at(page_size);
                register_command = RegisterCommand::System(SystemRegisterCommand {
                    header: SystemCommandHeader {
                        process_identifier: message_type[2],
                        msg_ident: Uuid::from_bytes(uuid_bytes.try_into().unwrap()),
                        read_ident: u64::from_be_bytes(rid_bytes.try_into().unwrap()),
                        sector_idx: u64::from_be_bytes(sec_bytes.try_into().unwrap()),
                    },
                    content: SystemRegisterCommandContent::Value {
                        timestamp: u64::from_be_bytes(ts_bytes.try_into().unwrap()),
                        write_rank: value_wr[0],
                        sector_data: SectorVec(Vec::from(sector_data)),
                    },
                })
            }
            MessageType::WriteProc => {
                //same size of Value, which is 8 + (32+16+4096)
                let mut rest_of_message: Vec<u8> = vec![0; 48 + page_size];
                data.read_exact(rest_of_message.as_mut())?;
                //Uuid
                let (uuid_bytes, rest) = rest_of_message.split_at(16);
                //read ident
                let (rid_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                //sector idx
                let (sec_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                //timestamp
                let (ts_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                let (_padding, rest) = rest.split_at(7);
                let (value_wr, rest) = rest.split_at(1);
                let (sector_data, _rest) = rest.split_at(page_size);
                register_command = RegisterCommand::System(SystemRegisterCommand {
                    header: SystemCommandHeader {
                        process_identifier: message_type[2],
                        msg_ident: Uuid::from_bytes(uuid_bytes.try_into().unwrap()),
                        read_ident: u64::from_be_bytes(rid_bytes.try_into().unwrap()),
                        sector_idx: u64::from_be_bytes(sec_bytes.try_into().unwrap()),
                    },
                    content: SystemRegisterCommandContent::WriteProc {
                        timestamp: u64::from_be_bytes(ts_bytes.try_into().unwrap()),
                        write_rank: value_wr[0],
                        data_to_write: SectorVec(Vec::from(sector_data)),
                    },
                })
            }
            MessageType::Ack => {
                let mut rest_of_message: Vec<u8> = vec![0; 48];
                data.read_exact(rest_of_message.as_mut())?;
                //Uuid
                let (uuid_bytes, rest) = rest_of_message.split_at(16);
                //read ident
                let (rid_bytes, rest) = rest.split_at(std::mem::size_of::<u64>());
                //sector idx
                let (sec_bytes, _rest) = rest.split_at(std::mem::size_of::<u64>());
                register_command = RegisterCommand::System(SystemRegisterCommand{
                    header: SystemCommandHeader {
                        process_identifier: message_type[2],
                        msg_ident: Uuid::from_bytes(uuid_bytes.try_into().unwrap()),
                        read_ident: u64::from_be_bytes(rid_bytes.try_into().unwrap()),
                        sector_idx: u64::from_be_bytes(sec_bytes.try_into().unwrap()),
                    },
                    content: SystemRegisterCommandContent::Ack
                })
            }
            _ => return Err(Error::new(ErrorKind::Other, "unknown message type")),
        }
        Ok(register_command)
    }

    pub fn serialize_register_command(
        cmd: &RegisterCommand,
        writer: &mut dyn Write,
    ) -> Result<(), Error> {
        let proc_padding: [u8; 2] = [0x00, 0x00];
        let client_padding: [u8; 3] = [0x00, 0x00, 0x00];
        let value_wr_padding: [u8; 7] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        match cmd {
            RegisterCommand::Client(client_register_command) => {
                writer.write_all(MAGIC_NUMBER.as_ref())?;
                writer.write_all(client_padding.as_ref())?;
                match client_register_command.content.clone() {
                    ClientRegisterCommandContent::Read => {
                        writer.write([MessageType::ClientRead as u8].as_ref())?;
                        writer.write_all(
                            client_register_command
                                .header
                                .request_identifier
                                .to_be_bytes()
                                .as_ref(),
                        )?;
                        writer.write_all(
                            client_register_command
                                .header
                                .sector_idx
                                .to_be_bytes()
                                .as_ref(),
                        )?;
                        //read has no content
                        //only hmac left(added on upper level)
                    }
                    ClientRegisterCommandContent::Write { data } => {
                        writer.write([MessageType::ClientWrite as u8].as_ref())?;
                        writer.write_all(
                            client_register_command
                                .header
                                .request_identifier
                                .to_be_bytes()
                                .as_ref(),
                        )?;
                        writer.write_all(
                            client_register_command
                                .header
                                .sector_idx
                                .to_be_bytes()
                                .as_ref(),
                        )?;
                        writer.write_all(data.0.as_slice())?;
                        //hmac will be added by layer above
                    }
                }
            }
            RegisterCommand::System(system_register_command) => {
                writer.write_all(MAGIC_NUMBER.as_ref())?;
                writer.write_all(proc_padding.as_ref())?;
                writer.write_all([system_register_command.header.process_identifier].as_ref())?;
                match system_register_command.content.clone() {
                    SystemRegisterCommandContent::ReadProc => {
                        writer.write_all([MessageType::ReadProc as u8].as_ref())?;
                    }
                    SystemRegisterCommandContent::Value { .. } => {
                        writer.write_all([MessageType::Value as u8].as_ref())?;
                    }
                    SystemRegisterCommandContent::WriteProc { .. } => {
                        writer.write_all([MessageType::WriteProc as u8].as_ref())?;
                    }
                    SystemRegisterCommandContent::Ack => {
                        writer.write_all([MessageType::Ack as u8].as_ref())?;
                    }
                }
                //uuid, read identifier, sector index, common for all message types
                writer.write_all(system_register_command.header.msg_ident.as_bytes())?;
                writer.write_all(
                    system_register_command
                        .header
                        .read_ident
                        .to_be_bytes()
                        .as_ref(),
                )?;
                writer.write_all(
                    system_register_command
                        .header
                        .sector_idx
                        .to_be_bytes()
                        .as_ref(),
                )?;

                //message content
                match system_register_command.content.clone() {
                    SystemRegisterCommandContent::Value {
                        timestamp,
                        write_rank,
                        sector_data,
                    } => {
                        writer.write_all(timestamp.to_be_bytes().as_ref())?;
                        //7 bytex of padding, then wr
                        writer.write_all(value_wr_padding.as_ref())?;
                        writer.write_all([write_rank].as_ref())?;
                        writer.write_all(sector_data.0.as_slice())?;
                    }
                    SystemRegisterCommandContent::WriteProc {
                        timestamp,
                        write_rank,
                        data_to_write,
                    } => {
                        writer.write_all(timestamp.to_be_bytes().as_ref())?;
                        //7 bytex of padding, then wr
                        writer.write_all(value_wr_padding.as_ref())?;
                        writer.write_all([write_rank].as_ref())?;
                        writer.write_all(data_to_write.0.as_slice())?;
                    }
                    _ => {} //no content for other messages
                }
            }
        }
        Ok(())
    }
}

pub mod register_client_public {
    use crate::{serialize_register_command, RegisterCommand, SystemRegisterCommand, HmacSha256};
    use std::io::Write;
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt};
    use tokio::net::TcpStream;
    use hmac::Mac;
    use tokio::sync::Mutex;
    use std::collections::{HashMap, HashSet};
    use std::ops::DerefMut;
    use uuid::Uuid;
    use tokio::time::Duration;

    pub(crate) struct MyRegisterClient {
        pub(crate) messages_to_send : Arc<Mutex<HashMap<Uuid, (HashSet<u8>, Vec<u8>)>>>,
        pub(crate) tcp_locations: Vec<(String, u16)>,
        pub(crate) system_mac : HmacSha256,
    }

    impl MyRegisterClient{
       pub async fn send_all_not_sent_messages(&self){
         //   println!("sending all messages");
            loop {
              //  println!("sending not sent messages every 500ms..");
                let mut guard = self.messages_to_send.lock().await;
                let msgs_map = guard.deref_mut();
                let mut messages_to_process: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
                for (_k, (rec, cmd)) in msgs_map {
                   // println!("map msg");
                    for process in rec.iter() {
                        //println!("process {:?} didn't receive it yet", process);
                        if !messages_to_process.contains_key(process) {
                            messages_to_process.insert(process.clone(), vec![]);
                        }
                        let vec = messages_to_process.get_mut(process).unwrap();
                        vec.push(cmd.to_vec());
                    }
                }
                drop(guard);
                let mut tasks = vec![];
                let tcp_locations = self.tcp_locations.clone();

                for (i, addr) in tcp_locations.iter().cloned().enumerate() {
                    let cloned_messages = messages_to_process.clone();
                    tasks.push(tokio::spawn(async move {
                        if cloned_messages.contains_key(&(i as u8)) {
                            let messages = cloned_messages.get(&(i as u8)).unwrap();
                            let stream = TcpStream::connect(addr).await;
                            match stream {
                                Ok(mut stream) => {
                                    //TODO check if write succeeds
                                    for msg in messages.iter().rev() {
                                      //  println!("found not sent messages");
                                        stream.write_all(msg.as_slice()).await.unwrap();
                                    }
                                }
                                Err(e) => {
                                    log::debug!("couldn't connect with client {:#}", e);
                                }
                            }
                        } else {
                            return;
                        }
                    }));
                }
                for x in tasks {
                    match x.await {
                        Ok(_) => {}
                        Err(e) => {
                            log::debug!("couldn't send data to client {:}", e);
                        }
                    }
                }
                //messages_to_process contains messagess for every process to send
                //give some extra time for every message in the queue, so we don't end up in situation
                //such as we keep rebroadcasting messages before we're able to send answers to them
                tokio::time::sleep(Duration::from_millis(500)).await;
            }


        }
    }
    #[async_trait::async_trait]
    impl RegisterClient for MyRegisterClient {
        async fn send(&self, msg: Send) {
            //add message to 'not yet confirmed'
            let mut writer : Vec<u8> = vec![];
            let serialized_msg = serialize_register_command(&RegisterCommand::System((&*msg.cmd).clone()), writer.by_ref());
            if serialized_msg.is_ok(){
                let mut mac = self.system_mac.clone();
                mac.update(writer.as_slice());
                let mac_bytes = mac.finalize().into_bytes();
                writer.extend_from_slice(mac_bytes.as_slice());
                //save message, for maybe future sends
                let mut hashset = HashSet::new();
                hashset.insert((msg.target-1) as u8);
                let mut guard = self.messages_to_send.lock().await;
                let msgs_map = guard.deref_mut();
                msgs_map.insert(msg.cmd.header.msg_ident, (hashset, writer.clone()));
                drop(guard);


                let addr = self.tcp_locations.get(msg.target-1).unwrap();
                let stream = TcpStream::connect(addr).await;
                match stream{
                    Ok(mut socket) => {
                        socket.write_all(writer.as_slice()).await.ok();
                    }
                    Err(_) => {}
                }
            }
            else{
                println!("couldn't serialize");
            }
        }

        async fn broadcast(&self, msg: Broadcast) {
         // add to messages for which we didnt receive response yet
            let mut writer: Vec<u8> = vec![];
            let msg_uuid = msg.cmd.header.msg_ident.clone();
            let rc = RegisterCommand::System((*msg.cmd).clone());
            serialize_register_command(&rc, writer.by_ref()).unwrap();
            let mut mac = self.system_mac.clone();
            mac.update(writer.as_slice());
            let mac_bytes = mac.finalize().into_bytes();
            writer.extend_from_slice(mac_bytes.as_slice());

            let mut broadcast_set = HashSet::new();
            for i in 0..self.tcp_locations.len(){
                broadcast_set.insert(i as u8);
            }
            let mut guard = self.messages_to_send.lock().await;
            let msgs = guard.deref_mut();
            msgs.insert(msg_uuid, (broadcast_set, writer.clone()));
            drop(guard);


            //send message for the first time
            let mut tasks = vec![];
            //self.send_all_not_sent_messages().await;
            for addr in self.tcp_locations.clone(){
                let cloned_msg = writer.clone();
                tasks.push(tokio::task::spawn(async move{
                    let stream = TcpStream::connect(addr).await;
                    match stream{
                        Ok(mut socket) => {
                            socket.write_all(cloned_msg.as_slice()).await.ok();
                        }
                        Err(_) => {}
                    }
                }));
            }
            for x in tasks{
                match x.await{
                    Ok(_) => {}
                    Err(err) => {
                        log::debug!("error when awaiting for task: {:?}", err);
                    }
                }
            }
        }
    }
    #[async_trait::async_trait]
    /// We do not need any public implementation of this trait. It is there for use
    /// in AtomicRegister. In our opinion it is a safe bet to say some structure of
    /// this kind must appear in your solution.
    pub trait RegisterClient: core::marker::Send + core::marker::Sync {
        /// Sends a system message to a single process.
        async fn send(&self, msg: Send);

        /// Broadcasts a system message to all processes in the system, including self.
        async fn broadcast(&self, msg: Broadcast);
    }

    pub struct Broadcast {
        pub cmd: Arc<SystemRegisterCommand>,
    }

    pub struct Send {
        pub cmd: Arc<SystemRegisterCommand>,
        /// Identifier of the target process. Those start at 1.
        pub target: usize,
    }
}

pub mod stable_storage_public {
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) struct MyStableStorage {
        pub(crate) root_dir: PathBuf,
    }

    const BASE64_ALPHABET: [char; 64] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '+', '-',
    ];

    impl MyStableStorage {
        //encoding algorithm based on https://levelup.gitconnected.com/implementing-base64-in-rust-34ef6db1e73a
        fn encode_key(content: &str) -> String {
            let characters: &[u8] = content.as_bytes();
            let mut base64_output = Vec::with_capacity((characters.len() / 3 + 1) * 4);

            let mut counter = 0;
            while counter + 3 <= characters.len() {
                let first_base64_character =
                    MyStableStorage::extract_first_character_bits(characters[counter]);
                let second_base64_character = MyStableStorage::extract_second_character_bits(
                    characters[counter],
                    characters[counter + 1],
                );
                let third_base64_character = MyStableStorage::extract_third_character_bits(
                    characters[counter + 1],
                    characters[counter + 2],
                );
                let fourth_base64_character = characters[counter + 2] & 0b00111111;

                base64_output.append(&mut vec![
                    BASE64_ALPHABET[first_base64_character as usize],
                    BASE64_ALPHABET[second_base64_character as usize],
                    BASE64_ALPHABET[third_base64_character as usize],
                    BASE64_ALPHABET[fourth_base64_character as usize],
                ]);

                counter += 3;
            }

            if counter + 1 == characters.len() {
                let first_base64_character =
                    MyStableStorage::extract_first_character_bits(characters[counter]);
                let second_base64_character =
                    MyStableStorage::extract_second_character_bits(characters[counter], 0);

                base64_output.append(&mut vec![
                    BASE64_ALPHABET[first_base64_character as usize],
                    BASE64_ALPHABET[second_base64_character as usize],
                    '=',
                    '=',
                ]);
            } else if counter + 2 == characters.len() {
                let first_base64_character =
                    MyStableStorage::extract_first_character_bits(characters[counter]);
                let second_base64_character = MyStableStorage::extract_second_character_bits(
                    characters[counter],
                    characters[counter + 1],
                );
                let third_base64_character =
                    MyStableStorage::extract_third_character_bits(characters[counter + 1], 0);

                base64_output.append(&mut vec![
                    BASE64_ALPHABET[first_base64_character as usize],
                    BASE64_ALPHABET[second_base64_character as usize],
                    BASE64_ALPHABET[third_base64_character as usize],
                    '=',
                ]);
            }

            base64_output.into_iter().collect::<String>()
        }
        fn extract_first_character_bits(first_byte: u8) -> u8 {
            (first_byte & 0b1111100) >> 2
        }

        fn extract_second_character_bits(first_byte: u8, second_byte: u8) -> u8 {
            (first_byte & 0b00000011) << 4 | ((second_byte & 0b11110000) >> 4)
        }

        fn extract_third_character_bits(second_byte: u8, third_byte: u8) -> u8 {
            (second_byte & 0b00001111) << 2 | ((third_byte & 0b11000000) >> 6)
        }
    }
    const MAX_KEY_SIZE: usize = 255;

    #[async_trait::async_trait]
    impl StableStorage for MyStableStorage {
        async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
            if key.len() > MAX_KEY_SIZE {
                return Err("Key is too big".to_owned());
            }
            if value.len() > 65536 {
                return Err("value size is too big".to_owned());
            }
            let key = key.to_owned() + "!";
            let mut path = PathBuf::new();
            path.push(self.root_dir.clone());
            let encoded_key = MyStableStorage::encode_key(&key);
            if encoded_key.len() > MAX_KEY_SIZE {
                path.push(&encoded_key[..MAX_KEY_SIZE / 2]);
                tokio::fs::create_dir_all(path.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                path.push(&encoded_key[MAX_KEY_SIZE / 2..])
            } else {
                tokio::fs::create_dir_all(path.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                path.push(&*encoded_key);
            }
            let real_path = path;
            path = PathBuf::from(&self.root_dir);
            path.push("!tmp");
            let file = tokio::fs::File::create(path.clone()).await;
            match file {
                Ok(mut f) => match f.write_all(value).await {
                    Ok(_) => match tokio::fs::rename(path, real_path).await {
                        Ok(_) => f.sync_all().await.map_err(|e| e.to_string()),
                        Err(_) => Err("couldn't write atomically".to_owned()),
                    },
                    Err(_) => Err("couldn't write to file".to_owned()),
                },
                Err(err) => Err("couldn't write to file ".to_owned() +err.to_string().as_str()),
            }
        }

        async fn get(&self, key: &str) -> Option<Vec<u8>> {
            if key.len() > MAX_KEY_SIZE {
                return None;
            }
            let key = key.to_owned() + "!";
            let mut path = self.root_dir.clone();
            let encoded_key = MyStableStorage::encode_key(&key);
            if encoded_key.len() > MAX_KEY_SIZE {
                path.push(&encoded_key[..MAX_KEY_SIZE / 2]);
                path.push(&encoded_key[MAX_KEY_SIZE / 2..])
            } else {
                path.push(&*encoded_key);
            }
            let mut file = match tokio::fs::File::open(path).await {
                Ok(file) => file,
                Err(_) => return None,
            };
            let mut buf: Vec<u8> = vec![];
            match file.read_to_end(buf.as_mut()).await {
                Ok(_) => Some(buf.to_vec()),
                Err(_) => None,
            }
        }
    }

    #[async_trait::async_trait]
    /// A helper trait for small amount of durable metadata needed by the register algorithm
    /// itself. Again, it is only for AtomicRegister definition. StableStorage in unit tests
    /// is durable, as one could expect.
    pub trait StableStorage: Send + Sync {
        async fn put(&mut self, key: &str, value: &[u8]) -> Result<(), String>;

        async fn get(&self, key: &str) -> Option<Vec<u8>>;
    }
}
