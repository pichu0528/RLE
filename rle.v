module rle (
    clk,        
    nreset,     
    start,
    message_addr,   
    message_size,   
    rle_addr,   
    rle_size,   
    done,       
    port_A_clk,
    port_A_data_in,
    port_A_data_out,
    port_A_addr,
    port_A_we
    );

input   clk;
input   nreset;
// Initializes the RLE module

input   start;
// Tells RLE to start compressing the given frame

input   [31:0] message_addr;
// Starting address of the plaintext frame
// i.e., specifies from where RLE must read the plaintext frame

input   [31:0] message_size;
// Length of the plain text in bytes

input   [31:0] rle_addr;
// Starting address of the ciphertext frame
// i.e., specifies where RLE must write the ciphertext frame

input   [31:0] port_A_data_out;
// read data from the dpsram (plaintext)

output reg [31:0] port_A_data_in;
// write data to the dpsram (ciphertext)

output  [15:0] port_A_addr;
// address of dpsram being read/written

output  port_A_clk;
// clock to dpsram (drive this with the input clk)

output  port_A_we;
// read/write selector for dpsram

output reg [31:0] rle_size;
// Length of the compressed text in bytes

output  done; // done is a signal to indicate that encryption of the frame is complete

assign port_A_clk = clk;

reg [31:0] size_count;    //count of processed data
reg [31:0] port_A_addr_read;
reg [31:0] port_A_addr_write;
wire       read_req;
reg        write_req;
reg [1:0]  proc_count; //processing data 


parameter IDLE = 2'b00,
          READ_DATA = 2'b01,
          PROCESS = 2'b10,
          DONE = 2'b11;

reg [1:0] state,next_state;
always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
        state <= IDLE;
    else
        state <= next_state;
end

always@(*)
begin
    if(nreset == 1'b0)
        next_state = IDLE;
    else
    begin
        case(state)
        IDLE:
        begin
            if(start == 1'b1)
                next_state = READ_DATA;
            else
                next_state = IDLE;
        end
        READ_DATA:
        begin
            if(port_A_we == 1'b1)
                next_state = READ_DATA;
            else
                next_state = PROCESS;
        end
        PROCESS:
        begin
            if(size_count <= 32'd4 && (proc_count + 1 == size_count[2:0]))
                next_state = DONE;
            else if(proc_count == 2'd3)
                next_state = READ_DATA;
            else
                next_state = PROCESS;
        end
        DONE:
            next_state = IDLE;
        endcase
    end
end                                                                  

assign done = (state == IDLE);

always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
        size_count <= 32'd0;
    else if(state == IDLE && start == 1)
        size_count <= message_size;
    else if(read_req)
        size_count <= size_count - 4;
end

//control of the port_A_addr
always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
        port_A_addr_read <= 32'd0;
    else if(state == IDLE && start == 1)
        port_A_addr_read <= message_addr;
    else if(read_req)
        port_A_addr_read <= port_A_addr_read + 4;
end

always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
        port_A_addr_write <= 32'd0;
    else if(state == IDLE && start == 1'b1)
        port_A_addr_write <= rle_addr;
    else if(write_req)
        port_A_addr_write <= port_A_addr_write + 4;
end

//read control
assign read_req = (state == PROCESS && next_state == READ_DATA);

always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
        proc_count <= 2'd0;
    else if(state == PROCESS)
        proc_count <= proc_count + 1'd1;
    else
        proc_count <= 2'd0;
end

reg first_data_flag;
always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
        first_data_flag <= 1'd0;
    else if(state == PROCESS)
        first_data_flag <= 1'd1;
    else if(done)
        first_data_flag <= 1'd0;
end

reg [7:0] data_num;       //data number count
reg [7:0] data_value;     //previous data
reg [7:0] curr_data;      //current process data

reg       pos_cnt;        //ouput position count

always@(*)
begin
    case(proc_count)
    2'd0: curr_data = port_A_data_out[7:0];
    2'd1: curr_data = port_A_data_out[15:8];
    2'd2: curr_data = port_A_data_out[23:16];
    2'd3: curr_data = port_A_data_out[31:24];
    endcase
end

always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
    begin
        data_num <= 8'd0;
        data_value <= 8'd0;
        pos_cnt <= 1'd0;
    end
    else if(start == 1'b1)
    begin
        data_num <= 8'd0;
        data_value <= 8'd0;
        pos_cnt <= 1'd0;
    end
    else if(state == PROCESS && first_data_flag == 1'b0)
    begin
        data_num <= 8'd1;
        data_value <= port_A_data_out[7:0];
    end
    else if(state == PROCESS)
    begin
        if(data_value == curr_data)
            data_num <= data_num + 1;
        else
        begin
            pos_cnt <= pos_cnt + 1;
            data_num <= 8'd1;
            data_value <= curr_data;
        end
    end
end

reg remain_data;
always@(posedge clk or negedge nreset)
begin
    if(nreset == 1'b0)
    begin
        port_A_data_in <= 32'd0;
        write_req <= 1'd0;
        rle_size <= 0;
        remain_data <= 0;
    end
    else if(start == 1'b1)
    begin
        port_A_data_in <= 32'd0;
        write_req <= 1'd0;
        rle_size <= 0;
        remain_data <= 0;
    end
    else if(state == PROCESS && first_data_flag == 1'b1)
    begin
        if(data_value != curr_data)
        begin
            if(pos_cnt == 1'b0)
            begin
                port_A_data_in[15:0] <= {data_value,data_num};
                if(next_state == DONE)
                begin
                    port_A_data_in[31:16] <= {curr_data,8'b01};
                    write_req <= 1'b1;
                    rle_size <= rle_size + 4;
                end
                else
                    write_req <= 1'b0;
            end                
            else
            begin 
                port_A_data_in[31:16] <= {data_value,data_num};
                write_req <= 1'b1;
                rle_size <= rle_size + 4;
                remain_data <= (next_state == DONE) ? 1'b1 : 1'b0;
            end
        end
        else
            write_req <= 1'b0;
    end
    else if(state == DONE && remain_data)
    begin
        port_A_data_in <= {16'b0,data_value,data_num};
        rle_size <= rle_size + 2;
        write_req <= 1'b1;
        remain_data <= 1'b0;
    end
    else
        write_req <= 1'b0;
end

//write or read
assign port_A_we = write_req ? 1'b1 : 1'b0;
assign port_A_addr = write_req ? port_A_addr_write : port_A_addr_read;

endmodule


