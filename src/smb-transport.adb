with Ada.Exceptions;
with Ada.Streams;
with SMB.Core_Framing;
with SMB.Core_Transport;
with SMB.Heap_Owner;

package body SMB.Transport is
   use type Ada.Exceptions.Exception_Id;
   use type Ada.Real_Time.Time;
   use type Ada.Streams.Stream_Element_Offset;
   use type GNAT.Sockets.Error_Type;
   use type GNAT.Sockets.Selector_Status;
   use type GNAT.Sockets.Socket_Type;

   --  Frame-sized buffers (up to 1 MiB) live on the heap and sockets are
   --  read in bounded chunks, so a frame does not have to fit on the stack.
   Receive_Chunk_Size : constant := 16_384;
   type Frame_Buffer is access Ada.Streams.Stream_Element_Array;
   package Frame_Owners is new SMB.Heap_Owner
     (Ada.Streams.Stream_Element_Array, Frame_Buffer);
   type Packet_Buffer is access SMB.Bytes;
   package Packet_Owners is new SMB.Heap_Owner (SMB.Bytes, Packet_Buffer);

   procedure Wait_For
     (Channel : Connection; Writing : Boolean; Deadline : Ada.Real_Time.Time) is
      Reads, Writes : GNAT.Sockets.Socket_Set_Type;
      State : GNAT.Sockets.Selector_Status;
   begin
      loop
         declare
            Remaining : Duration :=
              Ada.Real_Time.To_Duration (Deadline - Ada.Real_Time.Clock);
         begin
            State := GNAT.Sockets.Expired;
            if Remaining <= 0.0 then
               raise SMB.Transport_Error with "SMB socket operation timed out";
            end if;
            GNAT.Sockets.Empty (Reads);
            GNAT.Sockets.Empty (Writes);
            if Writing then
               GNAT.Sockets.Set (Writes, Channel.Socket);
            else
               GNAT.Sockets.Set (Reads, Channel.Socket);
            end if;
            if Remaining > GNAT.Sockets.Forever then
               Remaining := GNAT.Sockets.Forever;
            end if;
            begin
               GNAT.Sockets.Check_Selector
                 (GNAT.Sockets.Null_Selector, Reads, Writes, State,
                  GNAT.Sockets.Selector_Duration (Remaining));
            exception
               when E : GNAT.Sockets.Socket_Error =>
                  if GNAT.Sockets.Resolve_Exception (E) =
                    GNAT.Sockets.Interrupted_System_Call
                  then
                     null;
                  else
                     raise SMB.Transport_Error with
                       Ada.Exceptions.Exception_Message (E);
                  end if;
            end;
            if State = GNAT.Sockets.Completed then
               return;
            elsif State /= GNAT.Sockets.Expired then
               raise SMB.Transport_Error with "SMB socket selector failed";
            end if;
         end;
      end loop;
   end Wait_For;

   procedure Read_Exact
     (Channel : Connection; Buffer : out SMB.Bytes;
      Deadline : Ada.Real_Time.Time) is
      Position : Natural := 0;
      Status : SMB.Core_Status;
   begin
      Buffer := (others => 0);
      while Position < Buffer'Length loop
         Wait_For (Channel, False, Deadline);
         declare
            Last : Ada.Streams.Stream_Element_Offset;
            Count : constant Ada.Streams.Stream_Element_Offset :=
              Ada.Streams.Stream_Element_Offset
                (Natural'Min (Buffer'Length - Position, Receive_Chunk_Size));
            Received : Ada.Streams.Stream_Element_Array
              (1 .. Receive_Chunk_Size) := (others => 0);
            Chunk : Ada.Streams.Stream_Element_Array renames
              Received (1 .. Count);
            Retry : Boolean := False;
         begin
            begin
               GNAT.Sockets.Receive_Socket (Channel.Socket, Chunk, Last);
            exception
               when E : GNAT.Sockets.Socket_Error =>
                  if GNAT.Sockets.Resolve_Exception (E) =
                       GNAT.Sockets.Interrupted_System_Call
                    or else GNAT.Sockets.Resolve_Exception (E) =
                       GNAT.Sockets.Resource_Temporarily_Unavailable
                  then
                     Retry := True;
                  else
                     raise;
                  end if;
            end;
            if Retry then
               null;
            else
               declare
                  Window : SMB.Bytes renames Buffer
                    (Buffer'First + Position ..
                       Buffer'First + Position + Natural (Count) - 1);
                  Window_Position : Natural := 0;
               begin
                  SMB.Core_Transport.Receive_Chunk
                    (Chunk, Last, Window, Window_Position, Status);
                  Position := Position + Window_Position;
               end;
               if Status /= SMB.Ok then
                  raise SMB.Transport_Error with
                    (if Last < Chunk'First then "peer closed SMB connection"
                     else "invalid SMB receive result");
               end if;
            end if;
         end;
      end loop;
   end Read_Exact;

   procedure Write_Exact
     (Channel : Connection; Buffer : Ada.Streams.Stream_Element_Array;
      Deadline : Ada.Real_Time.Time) is
      Position : Natural := 0;
      Status : SMB.Core_Status;
   begin
      while Position < Buffer'Length loop
         Wait_For (Channel, True, Deadline);
         declare
            First : Ada.Streams.Stream_Element_Offset;
            Last : Ada.Streams.Stream_Element_Offset;
            Retry : Boolean := False;
         begin
            SMB.Core_Transport.Prepare_Write
              (Buffer, Position, First, Status);
            if Status /= SMB.Ok then
               raise SMB.Transport_Error with "invalid SMB send position";
            end if;
            begin
               GNAT.Sockets.Send_Socket
                 (Channel.Socket, Buffer (First .. Buffer'Last), Last);
            exception
               when E : GNAT.Sockets.Socket_Error =>
                  if GNAT.Sockets.Resolve_Exception (E) =
                       GNAT.Sockets.Interrupted_System_Call
                    or else GNAT.Sockets.Resolve_Exception (E) =
                       GNAT.Sockets.Resource_Temporarily_Unavailable
                  then
                     Retry := True;
                  else
                     raise;
                  end if;
            end;
            if Retry then
               null;
            else
               SMB.Core_Transport.Advance_Write
                 (Buffer, Last, Position, Status);
               if Status /= SMB.Ok then
                  raise SMB.Transport_Error with
                    (if Last < First then "peer closed SMB connection"
                     else "invalid SMB send result");
               end if;
            end if;
         end;
      end loop;
   end Write_Exact;

   procedure Connect
     (Channel : in out Connection;
      Host : String;
      Port : Positive := 445;
      Timeout_Seconds : Duration := 10.0) is
      Address : GNAT.Sockets.Sock_Addr_Type;
      State : GNAT.Sockets.Selector_Status;
   begin
      if Channel.Open then
         raise SMB.Invalid_State with "SMB transport is already connected";
      end if;
      if Host'Length = 0 or else Timeout_Seconds <= 0.0
        or else Port > Positive (GNAT.Sockets.Port_Type'Last)
      then
         raise SMB.Protocol_Error with "invalid SMB transport parameters";
      end if;
      Channel.Timeout := Timeout_Seconds;
      declare
         Host_Entry : constant GNAT.Sockets.Host_Entry_Type :=
           GNAT.Sockets.Get_Host_By_Name (Host);
      begin
         if GNAT.Sockets.Addresses_Length (Host_Entry) = 0 then
            raise SMB.Transport_Error with "host has no usable address";
         end if;
         Address := GNAT.Sockets.Network_Socket_Address
           (GNAT.Sockets.Addresses (Host_Entry),
            GNAT.Sockets.Port_Type (Port));
         GNAT.Sockets.Create_Socket (Channel.Socket, Address.Family);
         GNAT.Sockets.Connect_Socket
           (Channel.Socket, Address,
            GNAT.Sockets.Selector_Duration (Timeout_Seconds),
            Status => State);
         if State /= GNAT.Sockets.Completed then
            GNAT.Sockets.Close_Socket (Channel.Socket);
            Channel.Socket := GNAT.Sockets.No_Socket;
            raise SMB.Transport_Error with "SMB TCP connection timed out";
         end if;
         declare
            Nonblocking : GNAT.Sockets.Request_Type :=
              (Name => GNAT.Sockets.Non_Blocking_IO, Enabled => True);
         begin
            GNAT.Sockets.Control_Socket (Channel.Socket, Nonblocking);
         end;
         Channel.Open := True;
      end;
   exception
      when SMB.Transport_Error | SMB.Protocol_Error | SMB.Invalid_State =>
         raise;
      when E : others =>
         if Channel.Socket /= GNAT.Sockets.No_Socket then
            begin
               GNAT.Sockets.Close_Socket (Channel.Socket);
            exception
               when others => null;
            end;
            Channel.Socket := GNAT.Sockets.No_Socket;
         end if;
         raise SMB.Transport_Error with Ada.Exceptions.Exception_Message (E);
   end Connect;

   procedure Send_Frame (Channel : in out Connection; Packet : SMB.Bytes) is
      Status : SMB.Core_Status;
      Deadline : constant Ada.Real_Time.Time :=
        Ada.Real_Time.Clock + Ada.Real_Time.To_Time_Span (Channel.Timeout);
      Frame : Frame_Owners.Owner;
   begin
      if not Channel.Open then
         raise SMB.Invalid_State with "SMB transport is not connected";
      end if;
      if Packet'Length not in 64 .. SMB.Maximum_Frame_Size then
         raise SMB.Protocol_Error with "SMB packet length is outside the frame limit";
      end if;
      Frame.Item := new Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Packet'Length + 4));
      SMB.Core_Transport.Build_Frame (Packet, Frame.Item.all, Status);
      if Status /= SMB.Ok then
         raise SMB.Protocol_Error with "SMB frame construction failed";
      end if;
      Write_Exact (Channel, Frame.Item.all, Deadline);
   exception
      when E : others =>
         Close (Channel);
         if Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Invalid_State'Identity
         then
            raise;
         end if;
         raise SMB.Transport_Error with Ada.Exceptions.Exception_Message (E);
   end Send_Frame;

   function Receive_Deadline (Channel : Connection) return Ada.Real_Time.Time is
     (Ada.Real_Time.Clock + Ada.Real_Time.To_Time_Span (Channel.Timeout));

   function Receive_Frame (Channel : in out Connection) return SMB.Bytes is
   begin
      return Receive_Frame (Channel, Receive_Deadline (Channel));
   end Receive_Frame;

   function Receive_Frame
     (Channel : in out Connection; Deadline : Ada.Real_Time.Time)
      return SMB.Bytes is
      Header : SMB.Core_Framing.Frame_Header;
      Status : SMB.Core_Status;
      Length : Natural;
   begin
      if not Channel.Open then
         raise SMB.Invalid_State with "SMB transport is not connected";
      end if;
      Read_Exact (Channel, Header, Deadline);
      SMB.Core_Framing.Decode (Header, Length, Status);
      if Status /= SMB.Ok then
         raise SMB.Protocol_Error with "SMB response frame length is outside the limit";
      end if;
      declare
         Packet : Packet_Owners.Owner;
      begin
         Packet.Item := new SMB.Bytes (0 .. Length - 1);
         Read_Exact (Channel, Packet.Item.all, Deadline);
         return Packet.Item.all;
      end;
   exception
      when E : others =>
         Close (Channel);
         if Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Invalid_State'Identity
         then
            raise;
         end if;
         raise SMB.Transport_Error with Ada.Exceptions.Exception_Message (E);
   end Receive_Frame;

   procedure Close (Channel : in out Connection) is
   begin
      if Channel.Socket /= GNAT.Sockets.No_Socket then
         GNAT.Sockets.Close_Socket (Channel.Socket);
      end if;
      Channel.Socket := GNAT.Sockets.No_Socket;
      Channel.Open := False;
   exception
      when others =>
         Channel.Socket := GNAT.Sockets.No_Socket;
         Channel.Open := False;
   end Close;

   function Is_Open (Channel : Connection) return Boolean is (Channel.Open);
end SMB.Transport;
