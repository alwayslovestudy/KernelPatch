#ifndef BINDER_DEF_H
#define BINDER_DEF_H


#define BINDER_WRITE_READ 3224396289


#define BC_TRANSACTION 0x40406300
#define BR_REPLY        0x80407203
#define BR_NOOP      0x720c
#define BR_TRANSACTION_COMPLETE 0x7206


typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;

typedef struct binder_write_read_t
{
    binder_size_t write_size; /* bytes to write */
    binder_size_t write_consumed; /* bytes consumed by driver */
    binder_uintptr_t write_buffer;
    binder_size_t read_size; /* bytes to read */
    binder_size_t read_consumed; /* bytes consumed by driver */
    binder_uintptr_t read_buffer;
} binder_write_read;

typedef struct binder_transaction_data_t
{
    /* The first two are only used for bcTRANSACTION and brTRANSACTION,
     * identifying the target and contents of the transaction.
     */
    union
    {
        /* target descriptor of command transaction */
        __u32 handle;
        /* target descriptor of return transaction */
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie; /* target object cookie */
    __u32 code; /* transaction command */

    /* General information about the transaction. */
    __u32 flags;
    pid_t sender_pid;
    uid_t sender_euid;
    binder_size_t data_size; /* number of bytes of data */
    binder_size_t offsets_size; /* number of bytes of offsets */

    /* If this transaction is inline, the data immediately
     * follows here; otherwise, it ends with a pointer to
     * the data buffer.
     */
    union
    {
        struct
        {
            /* transaction data */
            binder_uintptr_t buffer;
            /* offsets from buffer to flat_binder_object structs */
            binder_uintptr_t offsets;
        } ptr;
        __u8 buf[8];
    } data;
} binder_transaction_data;

typedef struct parcel_binder_transaction_data_t
{
    int32_t cmd;
    binder_transaction_data ta_data;
} __packed parcel_binder_transaction_data; //__packed attribute to prevent structure padding issues

#endif BINDER_DEF_H