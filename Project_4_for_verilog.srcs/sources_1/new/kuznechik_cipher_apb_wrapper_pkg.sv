package kuznechik_cipher_apb_wrapper_pkg;

    ///////////////////////
    // Cipher memory map //
    ///////////////////////

    typedef enum {
        DATA_OUT = 32'h0014,
        DATA_IN  = 32'h0004,
        CONTROL  = 32'h0000,
        
        //DATA_IN_0 = 32'h0004,
        DATA_IN_1 = 32'h0008,
        DATA_IN_2 = 32'h000C,
        DATA_IN_3 = 32'h0010,
                  
        //DATA_OUT_0 = 32'h0014,
        DATA_OUT_1 = 32'h0018,
        DATA_OUT_2 = 32'h001C,
        DATA_OUT_3 = 32'h0020
    } cipher_apb_addr_t;

    typedef enum {
        RST     = 0,
        REQ_ACK = 1,
        VALID   = 2,
        BUSY    = 3
    } cipher_control_t;

endpackage
