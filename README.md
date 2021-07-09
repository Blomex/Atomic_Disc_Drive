# Background

This is implementation of a distributed block device, called Atomic Disc Drive. 

It stores data in a distributed register, and can be used like any other block device.

Distributed register consists of multiple processes running in user space, possibly on many different machines. The block device driver connects to them using TCP. Also the processes themselves communicate using TCP. Processes can crash and recover at any time. Number of processes is fixed before the system is run, and every process will have its own directory on the disc.

Every sector of the block device is a separate atomic value stored in the distributed system, meaning the system supports a set of of atomic values, called also registers. Sectors have 4096 bytes.
