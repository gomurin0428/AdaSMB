with Ada.Real_Time;
with GNAT.Sockets;

package SMB.Transport is
   type Connection is limited private;

   procedure Connect
     (Channel : in out Connection;
      Host : String;
      Port : Positive := 445;
      Timeout_Seconds : Duration := 10.0);
   procedure Send_Frame (Channel : in out Connection; Packet : SMB.Bytes);
   function Receive_Frame (Channel : in out Connection) return SMB.Bytes;
   function Receive_Deadline (Channel : Connection) return Ada.Real_Time.Time;
   function Receive_Frame
     (Channel : in out Connection; Deadline : Ada.Real_Time.Time)
      return SMB.Bytes;
   procedure Close (Channel : in out Connection);
   function Is_Open (Channel : Connection) return Boolean;

private
   type Connection is limited record
      Socket : GNAT.Sockets.Socket_Type := GNAT.Sockets.No_Socket;
      Timeout : Duration := 10.0;
      Open : Boolean := False;
   end record;
end SMB.Transport;
