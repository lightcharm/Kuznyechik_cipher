`timescale 1ns / 1ps

module kuznechik_cipher(
    input clk_i,
    input resetn_i,
    input request_i,                        //������ ������� �� ������ ����������
    input ack_i,
    input [127:0] data_i,
    
    output logic busy_o,
    output logic valid_o,               //������ ���������� ������������� ������
    output logic [127:0] data_o
    );

//��������� ��� ��������� ��������
localparam IDLE = 3'b000;
localparam KEY_PHASE = 3'b001;
localparam S_PHASE = 3'b010;
localparam L_PHASE = 3'b011;
localparam FINISH = 3'b100;

//������ �� memory-������
logic [127:0] key_mem [0:9];

logic [7:0] S_box_mem [0:255];

logic [7:0] L_mul_16_mem  [0:255];
logic [7:0] L_mul_32_mem  [0:255];
logic [7:0] L_mul_133_mem [0:255];
logic [7:0] L_mul_148_mem [0:255];
logic [7:0] L_mul_192_mem [0:255];
logic [7:0] L_mul_194_mem [0:255];
logic [7:0] L_mul_251_mem [0:255];

initial begin
    $readmemh("keys.mem", key_mem);
    $readmemh("S_box.mem", S_box_mem);

    $readmemh("L_16.mem", L_mul_16_mem);
    $readmemh("L_32.mem", L_mul_32_mem);
    $readmemh("L_133.mem", L_mul_133_mem);
    $readmemh("L_148.mem", L_mul_148_mem);
    $readmemh("L_192.mem", L_mul_192_mem);
    $readmemh("L_194.mem", L_mul_194_mem);
    $readmemh("L_251.mem", L_mul_251_mem);
end

//���������� ��������� ��������
logic [3:0] state = 4'b0;                              //������� ���������
logic [127:0] data = 128'h0;                       //������ ���������
logic [127:0] data_in_process = 128'h0;     //������ � �������� ����������
logic [4:0] round_counter = 5'b0;               //������� ���-�� �������
logic [7:0] summ_Galua = 8'b0;                 //��������� ���������� �������� XOR
logic [127:0] data_galua_shift = 128'h0;    //����� ����� �������� XOR
logic [4:0] index_for_L_phase = 5'b0;        //������� 16 ��������
logic [127:0] data_galua = 128'h0;            //��������� ����� ����� �����
logic [127:0] data_S_phase = 128'h0;       //��������� S_phase
logic [127:0] data_from_S_to_L = 128'h0;            //��������� ����� S_phase
logic [127:0] data_from_K_to_S = 128'h0;            //��������� ����� K_phase

always_ff @(posedge clk_i or negedge resetn_i) begin
    if (~resetn_i) begin    //������ ������ - �������� ��� ��������
        data_o = 0;
        data = 0;
        round_counter = 0;
        summ_Galua = 0;
        data_galua_shift = 0;
        data_S_phase = 0;
        data_from_S_to_L = 0;
        data_from_K_to_S = 0;
        index_for_L_phase = 0;
        busy_o = 0;
        valid_o = 0;
        
        state = IDLE;
    end
    else begin
        case (state)
            IDLE: begin
                if (request_i) begin   //���� ������ ������ �� ������ ����������
                    valid_o = 0;
                    busy_o = 1;
                    index_for_L_phase = 5'b0;
                    round_counter = 5'b0;
                    data = data_i;
                    
                    state = KEY_PHASE;
                end
            end
            KEY_PHASE: begin
                //���������� ��������� ����� �� �������� ������ ������
                data_in_process = data ^ key_mem[round_counter];
                data_from_K_to_S = data_in_process;
                
                if (round_counter < 9) begin
                    //��������� ���� - S_phase
                    state = S_PHASE;
                end
                //���� ������ 10-�� ������ ����������
                else if (round_counter == 9) begin
                    data_o = data_in_process;
                    busy_o = 0;
                    valid_o = 1;
                    
                    state = FINISH;
                end
                else if (round_counter > 9) begin
                    $display("Error. round_counter > 9");
                end
            end
            S_PHASE: begin
                //������ ���� ������ ���� �������� � �����. � �������� S
                data_S_phase[7:0] = S_box_mem[data_from_K_to_S[7:0]];
                data_S_phase[15:8] = S_box_mem[data_from_K_to_S[15:8]];
                data_S_phase[23:16] = S_box_mem[data_from_K_to_S[23:16]];
                data_S_phase[31:24] = S_box_mem[data_from_K_to_S[31:24]];
                data_S_phase[39:32] = S_box_mem[data_from_K_to_S[39:32]];
                data_S_phase[47:40] = S_box_mem[data_from_K_to_S[47:40]];
                data_S_phase[55:48] = S_box_mem[data_from_K_to_S[55:48]];
                data_S_phase[63:56] = S_box_mem[data_from_K_to_S[63:56]];
                data_S_phase[71:64] = S_box_mem[data_from_K_to_S[71:64]];
                data_S_phase[79:72] = S_box_mem[data_from_K_to_S[79:72]];
                data_S_phase[87:80] = S_box_mem[data_from_K_to_S[87:80]];
                data_S_phase[95:88] = S_box_mem[data_from_K_to_S[95:88]];
                data_S_phase[103:96] = S_box_mem[data_from_K_to_S[103:96]];
                data_S_phase[111:104] = S_box_mem[data_from_K_to_S[111:104]];
                data_S_phase[119:112] = S_box_mem[data_from_K_to_S[119:112]];
                data_S_phase[127:120] = S_box_mem[data_from_K_to_S[127:120]];
                //��������� ���� - L_phase
                data_from_S_to_L = data_S_phase;
                state = L_PHASE;
            end
            L_PHASE: begin
                if (index_for_L_phase < 16) begin //��������� ����������� 16 ���
                    data_galua[7:0] = L_mul_148_mem[data_from_S_to_L[127:120]];
                    data_galua[15:8] = L_mul_32_mem[data_from_S_to_L[119:112]];
                    data_galua[23:16] = L_mul_133_mem[data_from_S_to_L[111:104]];
                    data_galua[31:24] = L_mul_16_mem[data_from_S_to_L[103:96]];
                    data_galua[39:32] = L_mul_194_mem[data_from_S_to_L[95:88]];
                    data_galua[47:40] = L_mul_192_mem[data_from_S_to_L[87:80]];
                    data_galua[55:48] = data_from_S_to_L[79:72];
                    data_galua[63:56] = L_mul_251_mem[data_from_S_to_L[71:64]];
                    data_galua[71:64] = data_from_S_to_L[63:56];
                    data_galua[79:72] = L_mul_192_mem[data_from_S_to_L[55:48]];
                    data_galua[87:80] = L_mul_194_mem[data_from_S_to_L[47:40]];
                    data_galua[95:88] = L_mul_16_mem[data_from_S_to_L[39:32]];
                    data_galua[103:96] = L_mul_133_mem[data_from_S_to_L[31:24]];
                    data_galua[111:104] = L_mul_32_mem[data_from_S_to_L[23:16]];
                    data_galua[119:112] = L_mul_148_mem[data_from_S_to_L[15:8]];
                    data_galua[127:120] = data_from_S_to_L[7:0];
                    //���������� ������������ ������������ ������ � ���������� ������
                    summ_Galua = (((((((((((((((data_galua[127:120]) ^ data_galua[119:112]) ^ data_galua[111:104]) ^ data_galua[103:96]) ^ data_galua[95:88]) ^ data_galua[87:80]) ^ data_galua[79:72]) ^ data_galua[71:64]) ^ data_galua[63:56]) ^ data_galua[55:48]) ^ data_galua[47:40]) ^ data_galua[39:32]) ^ data_galua[31:24]) ^ data_galua[23:16]) ^ data_galua[15:8]) ^ data_galua[7:0];
                    
                    data_galua_shift[127:120] = summ_Galua;
                    data_galua_shift[119:0] = data_from_S_to_L[127:8];
                    data_from_S_to_L = data_galua_shift;
                    
                    index_for_L_phase = index_for_L_phase + 1;
                end
                else if (index_for_L_phase == 16) begin
                    //����� L_phase
                    data = data_from_S_to_L;
                    
                    index_for_L_phase = 5'b0;
                    round_counter = round_counter + 1;
                    
                    state = KEY_PHASE;
                end
                else if (index_for_L_phase > 16) begin
                    $display("Error. index_for_L_phase > 16");
                end
            end
            FINISH: begin
                if (request_i) begin  //���� �������� ���������
                    data = data_i;
                    index_for_L_phase = 5'b0;
                    round_counter = 5'b0;
                    busy_o = 1;
                    valid_o = 0;
                    
                    state = KEY_PHASE;
                end
                else if (ack_i) begin   //���� ������ ������ �� ������ ����������
                    valid_o = 0;
                    state = IDLE;
                end
            end
            default: begin
                $display("default");
            end
        endcase
    end
end

endmodule
