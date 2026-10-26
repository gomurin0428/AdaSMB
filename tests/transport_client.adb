with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with SMB;
with SMB.Transport;

procedure Transport_Client is
   use type Ada.Real_Time.Time;

   Channel : SMB.Transport.Connection;
   Packet : constant SMB.Bytes (0 .. SMB.Maximum_Frame_Size - 1) :=
     (others => 16#A5#);
   Deadline_Seconds : constant Duration := 0.5;
   Timed_Out : Boolean := False;
begin
   SMB.Transport.Connect
     (Channel, "127.0.0.1",
      Positive'Value (Ada.Command_Line.Argument (1)), Deadline_Seconds);
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
