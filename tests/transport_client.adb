with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with SMB;
with SMB.Transport;

procedure Transport_Client is
   use type Ada.Real_Time.Time;
   use type Ada.Exceptions.Exception_Id;
   use type SMB.Byte;

   Channel : SMB.Transport.Connection;
   Packet : constant SMB.Bytes (0 .. SMB.Maximum_Frame_Size - 1) :=
     (others => 16#A5#);
   Deadline_Seconds : constant Duration := 0.5;
   Timed_Out : Boolean := False;
   Port : constant Positive :=
     Positive'Value (Ada.Command_Line.Argument (1));
   Mode : constant String :=
     (if Ada.Command_Line.Argument_Count >= 2
      then Ada.Command_Line.Argument (2) else "stalled-write");

   procedure Receive_And_Echo (Expected_Length : Natural) is
      Data : constant SMB.Bytes := SMB.Transport.Receive_Frame (Channel);
   begin
      if Data'Length /= Expected_Length then
         raise Program_Error with "fragmented frame length mismatch";
      end if;
      for I in Data'Range loop
         if Data (I) /= SMB.Byte ((I - Data'First) mod 256) then
            raise Program_Error with "fragmented frame byte mismatch";
         end if;
      end loop;
      SMB.Transport.Send_Frame (Channel, Data);
   end Receive_And_Echo;

   procedure Test_Receive is
      Started : Ada.Real_Time.Time;
      Rejected : Boolean := False;
   begin
      if Mode = "fragmented" then
         Receive_And_Echo (512);
         SMB.Transport.Close (Channel);
         Ada.Text_IO.Put_Line ("fragmented receive and byte-exact echo passed");
         return;
      end if;
      Started := Ada.Real_Time.Clock;
      begin
         declare
            Unexpected : constant SMB.Bytes := SMB.Transport.Receive_Frame (Channel);
            pragma Unreferenced (Unexpected);
         begin
            raise Program_Error with "incomplete or invalid frame was accepted";
         end;
      exception
         when E : SMB.Protocol_Error | SMB.Transport_Error =>
            if Mode = "malformed-header" or else Mode = "oversized-header" then
               if Ada.Exceptions.Exception_Identity (E) /= SMB.Protocol_Error'Identity then
                  raise;
               end if;
            elsif Ada.Exceptions.Exception_Identity (E) /= SMB.Transport_Error'Identity then
               raise;
            end if;
            if Mode = "stalled-read" then
               declare
                  Elapsed : constant Duration := Ada.Real_Time.To_Duration
                    (Ada.Real_Time.Clock - Started);
               begin
                  if Elapsed < Deadline_Seconds * 0.9 or else Elapsed > 2.0
                    or else Ada.Strings.Fixed.Index
                      (Ada.Exceptions.Exception_Message (E), "timed out") = 0
                  then
                     raise Program_Error with "stalled receive violated its deadline";
                  end if;
               end;
            end if;
            Rejected := True;
      end;
      if not Rejected or else SMB.Transport.Is_Open (Channel) then
         raise Program_Error with "receive failure left the connection open";
      end if;
      begin
         declare
            Unexpected : constant SMB.Bytes := SMB.Transport.Receive_Frame (Channel);
            pragma Unreferenced (Unexpected);
         begin
            raise Program_Error with "failed receive connection was silently reused";
         end;
      exception
         when SMB.Invalid_State => null;
      end;
      SMB.Transport.Connect (Channel, "127.0.0.1", Port, Deadline_Seconds);
      Receive_And_Echo (64);
      SMB.Transport.Close (Channel);
      Ada.Text_IO.Put_Line
        ("receive failure and same-connection recovery passed: " & Mode);
   end Test_Receive;
begin
   SMB.Transport.Connect
     (Channel, "127.0.0.1", Port, Deadline_Seconds);
   if Mode /= "stalled-write" then
      Test_Receive;
      return;
   end if;
   for Attempt in 1 .. 64 loop
      declare
         Started : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
      begin
         SMB.Transport.Send_Frame (Channel, Packet);
      exception
         when E : SMB.Transport_Error =>
            if Ada.Strings.Fixed.Index
              (Ada.Exceptions.Exception_Message (E), "timed out") = 0
            then
               raise;
            end if;
            declare
               Elapsed : constant Duration := Ada.Real_Time.To_Duration
                 (Ada.Real_Time.Clock - Started);
            begin
               if Elapsed < Deadline_Seconds * 0.9 or else Elapsed > 2.0 then
                  raise Program_Error with "stalled write violated its deadline";
               end if;
            end;
            Timed_Out := True;
      end;
      exit when Timed_Out;
   end loop;
   if not Timed_Out then
      raise Program_Error with "test peer did not exert send backpressure";
   end if;
   if SMB.Transport.Is_Open (Channel) then
      raise Program_Error with "timed-out write left the connection open";
   end if;
   begin
      SMB.Transport.Send_Frame (Channel, Packet);
      raise Program_Error with "timed-out connection was silently reused";
   exception
      when SMB.Invalid_State => null;
   end;
   Ada.Text_IO.Put_Line ("stalled write deadline and invalidation passed");
exception
   when others =>
      SMB.Transport.Close (Channel);
      raise;
end Transport_Client;
