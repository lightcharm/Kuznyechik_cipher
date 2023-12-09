`timescale 1ns / 1ps

module kuznechik_cipher_apb_wrapper(
    input logic pclk_i,
    input logic presetn_i,
    
    input logic [31:0] paddr_i,
    
    //Control status
    input logic psel_i,
    input logic penable_i,
    input logic pwrite_i,
    
    //Write
    input logic [3:0][7:0] pwdata_i,
    input logic [3:0] pstrb_i,                  //������ ������ ���������� �����
    
    //Slave
    output logic pready_o,
    output logic [31:0] prdata_o,
    output logic pslverr_o
);

import kuznechik_cipher_apb_wrapper_pkg::*;

//parameter CONTROL = 32'h0000, 
//                   DATA_IN = 32'h0004,
//                   DATA_OUT = 32'h0014,
                  
//                   RST = 0,
//                   REQ_ACK = 1,
//                   VALID = 2,
//                   BUSY = 3,
                  
//                   DATA_IN_0 = 32'h0004,
//                   DATA_IN_1 = 32'h0008,
//                   DATA_IN_2 = 32'h000C,
//                   DATA_IN_3 = 32'h0010,
                  
//                   DATA_OUT_0 = 32'h0014,
//                   DATA_OUT_1 = 32'h0018,
//                   DATA_OUT_2 = 32'h001C,
//                   DATA_OUT_3 = 32'h0020;

logic [7:0] control_regs [3:0];
logic [31:0] data_in_regs [3:0];
logic [31:0] data_out_regs [3:0];

logic [127:0] cipher_data_i;
logic [127:0] cipher_data_o;
logic cipher_busy;
logic cipher_valid;

assign cipher_data_i = {data_in_regs[3], data_in_regs[2], data_in_regs[1], data_in_regs[0]};

always_ff @(posedge cipher_valid) begin
    data_out_regs[3] <= cipher_data_o[127:96];
    data_out_regs[2] <= cipher_data_o[95:64];
    data_out_regs[1] <= cipher_data_o[63:32];
    data_out_regs[0] <= cipher_data_o[31:0];
end

kuznechik_cipher cipher(
    .clk_i(pclk_i),
    .resetn_i(presetn_i && control_regs[RST]),
    .request_i(control_regs[REQ_ACK][0] && ~control_regs[VALID][0]),
    .ack_i(control_regs[REQ_ACK][0]),
    .data_i(cipher_data_i),
    
    .busy_o(cipher_busy),
    .valid_o(cipher_valid),
    .data_o(cipher_data_o)
);

//Control
assign pready_o = psel_i;
assign control_regs[BUSY] = cipher_busy;
assign control_regs[VALID] = cipher_valid;
assign control_regs[REQ_ACK] = (penable_i && pwrite_i && (paddr_i == CONTROL) && pstrb_i[REQ_ACK]) ? pwdata_i[REQ_ACK] : 0;

//Reading
always_ff @(posedge penable_i) begin
    if (~pwrite_i) begin
        case (paddr_i)
            CONTROL: begin
                prdata_o[31:24] <= control_regs[BUSY];
                prdata_o[23:16] <= control_regs[VALID];
                prdata_o[15:8] <= control_regs[REQ_ACK];
                prdata_o[7:0] <= control_regs[RST];
                
            end
            DATA_OUT_3: prdata_o <= data_out_regs[3];
            DATA_OUT_2: prdata_o <= data_out_regs[2];
            DATA_OUT_1: prdata_o <= data_out_regs[1];
            DATA_OUT: prdata_o <= data_out_regs[0];
            
            DATA_IN_3: prdata_o <= data_in_regs[3];
            DATA_IN_2: prdata_o <= data_in_regs[2];
            DATA_IN_1: prdata_o <= data_in_regs[1];
            DATA_IN: prdata_o <= data_in_regs[0];
            
            default: prdata_o <= 0;
        endcase
    end
end

//Writing
always_ff @(posedge penable_i) begin
    if (pwrite_i) begin
        case (paddr_i)
            CONTROL:
                if (pstrb_i[RST])
                    control_regs[RST] <= pwdata_i[RST];
            DATA_IN_3: begin
                data_in_regs[3][31:24] <= pwdata_i[3];
                data_in_regs[3][23:16] <= pwdata_i[2];
                data_in_regs[3][15:8] <= pwdata_i[1];
                data_in_regs[3][7:0] <= pwdata_i[0];
            end
            DATA_IN_2: begin
                data_in_regs[2][31:24] <= pwdata_i[3];
                data_in_regs[2][23:16] <= pwdata_i[2];
                data_in_regs[2][15:8] <= pwdata_i[1];
                data_in_regs[2][7:0] <= pwdata_i[0];
            end
            DATA_IN_1: begin
                data_in_regs[1][31:24] <= pwdata_i[3];
                data_in_regs[1][23:16] <= pwdata_i[2];
                data_in_regs[1][15:8] <= pwdata_i[1];
                data_in_regs[1][7:0] <= pwdata_i[0];
            end
            DATA_IN: begin
                data_in_regs[0][31:24] <= pwdata_i[3];
                data_in_regs[0][23:16] <= pwdata_i[2];
                data_in_regs[0][15:8] <= pwdata_i[1];
                data_in_regs[0][7:0] <= pwdata_i[0];
            end
        endcase
    end
end

always_comb begin
    pslverr_o <= 0;
    if (~psel_i) begin      //==0 => all ignored
        if (penable_i)
            pslverr_o <= 1;     //read-only
        if (pwrite_i)
            pslverr_o <= 1;
    end
    
    if (pwrite_i && (paddr_i == CONTROL) && pstrb_i[REQ_ACK] && control_regs[BUSY])     //module is busy
        pslverr_o <= 1; 
    
    if (paddr_i[1:0])       //�������� ������
        pslverr_o <= 1;

    if ((paddr_i > DATA_OUT_3))      //invalid address
        pslverr_o <= 1;
    else if (pwrite_i) begin
    //Write in read-only register
        if ((paddr_i == CONTROL) && (pstrb_i[VALID] || pstrb_i[BUSY]))
            pslverr_o <= 1; 
        if ((paddr_i >= DATA_OUT) && (paddr_i <= DATA_OUT_3))
            pslverr_o <= 1;
    end
end
endmodule
