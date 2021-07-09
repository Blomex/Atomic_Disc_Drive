# Linux driver

Driver serves as a test of binary interface of your solution, and is intended as a simple reference client for you to play with.

## Using the driver

The driver contains a `Makefile`. After typing `make` in this directory, a Linux module named
`atdd.ko` will appear in it. After`insmod atdd.ko
processes=(PORT_NUMBER:HOST)(,(PORT_NUMBER:HOST))* hmac=KEY_IN_HEXADECIMAL` a block device named
`atdd` will appear in `/dev` directory.
Processes are specified as a comma separated list of pairs of port number and host. Key is in
lower hex and contains 32 bytes total-so it has 64 characters when encoded. Example `insmod`
command is in `sample_insmod.sh` in the directory with the driver.
After inserting the module, performing block operations on the Linux device
results in sending them over TCP to the system. Note that some processes may be down or
crash during system operation, driver tries to cope with this situation.

Note that system can execute commands out-of-order of submission, the driver works around that
by having at most one command pending at any given moment. It is not efficient.

The version of Linux kernel which will be used for testing is 4.15.0-124-generic.

## QEMU

You can use qemu to run Linux.  To test your driver, you can create filesystem and use it:

    mkfs.ext2 /dev/atdd
    mount -t ext2 /dev/atdd /mnt/mount
    # after using the filesystem
    umount /mnt/mount

You can try to copy a large file to the system:

    dd if=liux.iso of=/dev/atdd bs=4096

This finishes the part about using the driver. The following sections are entirely optional.

# Improving the driver


The driver has two main issues. First of all, it sends commands to the system one by one,
that is it awaits completion of every read or write before the next one is submitted.
Secondly, it uses a single TCP connection to a single process of the system. One can image
that a driver could dispatch commands to multiple processes. This is safe to do, because
Linux issues requests to block devices in such a way, that they can be completed in any
order-modifications of the same sectors are managed by the kernel.

The driver was coded in a way to support multiple TCP connections (ATDD_THREADS_COUNT), but
sadly it does not work as expected and more than one threads result in garbled data on the
TCP stream. You can base your work on the provided driver or not. You will receive 3 points
if your driver will work noticeably faster than the reference one, and if it will
address issues mentioned above. Partial points are possible for interesting
working improvements. You can ask teachers on Moodle whether some improvement you are thinking of
would be interesting

Lastly, you can try to make driver as robust as possible. The one you are provided with was
never tested under extreme conditions, we tested only that is seems to handle crashes
of processes within the system.

If you are not interested, you can skip the rest of this file and only implement the distributed
register for which you can receive up to 30 points.

## Kernel modules, additional information

Now we provide more information about Linux modules. You can recheck 6th lab for basic
information. Code samples are for the kernel version from assignment description.

If you want to check source code of any Linux method, there is a
[place you can go to](https://elixir.bootlin.com/linux/latest/source).

## Kernel modules arguments

Linux kernel modules can receive arguments, similar to how `main` method can receive command
line arguments (even the kernel itself has arguments). Those are provided when
performing `insmod`, e.g.:

`insmod module.ko arg1=value1 arg2=4 ...`

There is a limit to the length of the full `insmod` command, but you do not need to worry
about this detail.

From module's point of view, it has to include `linux/moduleparam.h` header. Then parameters
can be accessed via:

```C
static char* arg1 = NULL;
module_param(arg1, charp, 0660);

static int arg2 = 2;
module_param(arg2, int, 0660);
```

First argument of `module_param` is name of the static variable to hold the argument.
Then there is a type description-`int`, `charp`, `bool` and `ushort` are some examples.
For the assignment only `charp` is necessary. Last one is permission to *sysfs*-you
can use `0` there. *Sysfs* is a special filesystem (it is not for storing files, but for
communication with objects inside of the kernel) exposed under `/sys` directory, and it
can be used from userspace to communicate read and set some data in the kernel. You do
not need to use *sysfs* explicitly for a simple driver.

There is also `module_param_array`, which accepts as argument an array of comma separated
values. Usage:

```C
static char* strings[MAX_FISH];
static int nr_strings;
module_param_array(strings, charp, &nr_strings, 0);
```

Here *type* specifies type of the element array.

## Cryptography in the kernel

There is a huge API for performing cryptographic operations in the kernel. It is tailored to
be composable, with focus on multiple implementations of every operation-think of pure
software implementation, or a hardware cycle-accurate one. We do not need any of
those, so we will only provide a short example for synchronous hashes
(it covers also HMAC):

```C
/* algorithm_name is name of the algorithm, other parameters are as-is.
  Valid algorithm_names can be found in /proc/crypto, under name sections */
struct crypto_shash *tmf = crypto_alloc_shash(algorithm_name,CRYPTO_ALG_TYPE_SHASH, 0);
crypto_shash_setkey(tmf, key_ptr_u8, key_len);
// defines helper for actual algorithm execution, with name `shash`
SHASH_DESC_ON_STACK(shash, tmf);
shash->tfm = tmf;
shash->flags = 0x0;
crypto_shash_digest(shash, data_ptr_u8, data_len, out_buf_ptr_u8);
```

Every `crypto` method can return errors in case of invalid configuration or lack of free memory.
The last method, `crypto_shash_digest`, results in hash being calculated to the *out_buf_ptr_u8*,
length is defined by specific hash algorithm.

## TCP

Driver needs a TCP client. It is quite similar to userspace TCP. Main type is
`struct socket` which represents any socket with the help of internal
type `struct sock` stored in field `sk`. Here is how it can be created in TCP case:

```C
struct socket *ptr = NULL;
// Pointer to a pointer is passed
sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, struct socket &ptr);
```

You can reference example from the template (`template/driver/tcp.c`) on how to connect
to a TCP server, and how to send and receive data. Data is received there
in non-blocking fashion, which you might find helpful.

You might also be interested in overriding low level behavior of socket - callbacks
which are called when data is ready, or when there is an error. Those callbacks can
be accessed as follows:

```C
struct socket *sock;
sock->sk->sk_user_data = void_ptr_to_some_private_data;
sock->sk->sk_data_ready = method_called_when_data_is_ready;
sock->sk->sk_error_report = method_called_on_error;
```

`sk_data_ready` and `sk_error_report` both receive `struct sock *` as a sole parameter
and return nothing.

## Kernel threads

You might want to spawn new threads of execution in the kernel. They have a simple API:

```C
#include <linux/kthread.h>


void task_method(void *data)
{
  //...
  // This is how you check if your task is supposed to stop
  if (kthread_should_stop())
    return;
}

void *data = DATA_TO_PASS_TO_THREAD;
// Task name can be formatted as in printf
struct task_struct *task = kthread_run(task_method, data, "my-name-%d", 7);

// Marks that task should stop, wakes the task and waits for it to exit.
kthread_stop(task);
```

## Static size hashmap

You might want to use hashmaps in your driver. Linux has this covered too! This is the data
structure which might make it possible to send multiple commands to the system at once.

```C
#include <linux/hashtable.h>

// 3 means size of hashtable will be 1 << 3.
// You can use this macro in struct definition.
DECLARE_HASHTABLE(tbl, 3);
hash_init(tbl);

struct h_node {
    void *data;
    struct hlist_node node;
};
uint64_t key;

struct h_node a, *cur;
unsigned bkt;

// In general, struct hlist_node must be allocated on the heap
hash_add(tbl, &a.node, key);

hash_for_each(tbl, bkt, cur, node) {
  // Iterate over the whole hashmap
}

hash_for_each_possible(tbl, cur, node, key) {
  // Iteration over possible values for a key.
  // Usually this block of code will execute once.
}

// removing elements
hash_del(&a.node);
```
