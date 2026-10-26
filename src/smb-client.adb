with Ada.Containers.Vectors;
with Ada.Exceptions;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with SMB.Clock;
with SMB.Core_Client;
with SMB.Core_Protocol;
with SMB.Core_Text;
with SMB.Core_Wire;
with SMB.NTLM;
with SMB.Wire;

package body SMB.Client is
   use type Ada.Exceptions.Exception_Id;
   use type SMB.Engine.Phase;
   use type SMB.Core_Client.Operation_Stage;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;

   File_Delete           : constant SMB.DWord := 16#0001_0000#;
   Disconnected : constant SMB.Engine.Phase := SMB.Engine.Disconnected;
   Authenticated : constant SMB.Engine.Phase := SMB.Engine.Authenticated;
   Share_Connected : constant SMB.Engine.Phase := SMB.Engine.Share_Connected;

   package Entry_Vectors is new Ada.Containers.Vectors
     (Index_Type => Natural, Element_Type => Directory_Entry);

   procedure Copy_Bytes
     (Target : in out SMB.Bytes; Target_Offset : Natural;
      Source : SMB.Bytes) is
   begin
      if Target_Offset > Target'Length
        or else Source'Length > Target'Length - Target_Offset
      then
         raise SMB.Protocol_Error with "SMB field exceeds packet bounds";
      end if;
      if Source'Length > 0 then
         Target (Target'First + Target_Offset
                   .. Target'First + Target_Offset + Source'Length - 1) := Source;
      end if;
   end Copy_Bytes;

   function Slice
     (Source : SMB.Bytes; Offset, Length : Natural) return SMB.Bytes is
   begin
      if Offset > Source'Length or else Length > Source'Length - Offset then
         raise SMB.Protocol_Error with "SMB field exceeds packet bounds";
      end if;
      if Length = 0 then
         return SMB.Bytes'(1 .. 0 => 0);
      end if;
      return Source
        (Source'First + Offset .. Source'First + Offset + Length - 1);
   end Slice;

   function Session_Identifier (Client : Connection) return SMB.QWord is
     (SMB.Engine.Current_Session_Id (Client.Engine_Core));

   function Tree_Identifier (Client : Connection) return SMB.DWord is
     (SMB.Engine.Current_Tree_Id (Client.Engine_Core));

   function Read_Limit (Client : Connection) return Natural is
     (SMB.Engine.Current_Max_Read (Client.Engine_Core));

   function Write_Limit (Client : Connection) return Natural is
     (SMB.Engine.Current_Max_Write (Client.Engine_Core));

   procedure Generate_Entropy (Output : out SMB.Bytes) is
      use Ada.Streams;
      use Ada.Streams.Stream_IO;
      File : File_Type;
      Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Output'Length));
      Last : Stream_Element_Offset;
   begin
      Open (File, In_File, "/dev/urandom");
      Read (File, Data, Last);
      if Last < Data'Last then
         Close (File);
         raise SMB.Authentication_Error with "operating-system entropy source failed";
      end if;
      for I in Output'Range loop
         Output (I) := SMB.Byte (Data (Data'First
           + Stream_Element_Offset (I - Output'First)));
      end loop;
      Close (File);
   exception
      when SMB.Authentication_Error =>
         raise;
      when E : others =>
         if Is_Open (File) then
            Close (File);
         end if;
         raise SMB.Authentication_Error with
           "cannot read operating-system entropy: "
           & Ada.Exceptions.Exception_Message (E);
   end Generate_Entropy;

   procedure Get_Entropy (Client : Connection; Output : out SMB.Bytes) is
   begin
      if Client.Entropy = null then
         Generate_Entropy (Output);
      else
         Client.Entropy (Output);
      end if;
   end Get_Entropy;

   procedure Clear_State (Client : in out Connection) is
      Engine_Status : SMB.Core_Status;
   begin
      SMB.Transport.Close (Client.Channel);
      SMB.Engine.Invalidate (Client.Engine_Core, Engine_Status);
      Client.Host := Ada.Strings.Unbounded.Null_Unbounded_String;
      Client.Last_Status := SMB.Success;
   end Clear_State;

   procedure Clear_State_Preserving_Status (Client : in out Connection) is
      Status : constant SMB.DWord := Client.Last_Status;
   begin
      Clear_State (Client);
      Client.Last_Status := Status;
   end Clear_State_Preserving_Status;

   procedure Require_Status (Client : in out Connection; Status : SMB.DWord) is
   begin
      Client.Last_Status := Status;
      if Status /= SMB.Success then
         raise SMB.NT_Status_Error with
           "server returned NTSTATUS" & SMB.DWord'Image (Status);
      end if;
   end Require_Status;

   function Exchange
     (Client : in out Connection;
      Command : SMB.Wire.Command_Code;
      Payload : SMB.Bytes;
      Sign_Request : Boolean := False;
      Require_Signed_Response : Boolean := False;
      Request_Session : SMB.QWord := 0;
      Response_Session : SMB.QWord := 0;
      Request_Tree : SMB.DWord := 0;
      Response_Tree : SMB.DWord := 0;
      Request_Amount : Natural := 0;
      Close_Token : SMB.Engine.Handle_Token := (others => 0)) return SMB.Bytes is
      Message : SMB.QWord;
      Expected : SMB.Engine.Request_Expectation;
      Engine_Status : SMB.Core_Status;
      Nt_Status : SMB.DWord;
      Wire_Status : SMB.Core_Status;
      Expected_Tree : constant SMB.DWord :=
        (if Command = SMB.Wire.Logoff_Command then 0
         else Tree_Identifier (Client));
   begin
      if Payload'Length > SMB.Maximum_Frame_Size - SMB.Core_Wire.Header_Size then
         raise SMB.Protocol_Error with "SMB request exceeds frame limit";
      end if;
      if Request_Session /= Session_Identifier (Client)
        or else Request_Tree /= Expected_Tree
        or else Response_Session /= Session_Identifier (Client)
        or else Response_Tree /= Expected_Tree
      then
         raise SMB.Invalid_State with "request identifiers disagree with session engine";
      end if;
      SMB.Engine.Begin_Request
        (Client.Engine_Core, SMB.Core_Wire.Command_Code (Command),
         Sign_Request, Require_Signed_Response, Message, Expected,
         Engine_Status, Request_Amount, Close_Token);
      if Engine_Status /= SMB.Ok then
         raise SMB.Invalid_State with
           "session engine rejected request: "
           & SMB.Core_Status'Image (Engine_Status);
      end if;
      declare
         Packet : SMB.Bytes
           (0 .. SMB.Core_Wire.Header_Size + Payload'Length - 1);
      begin
      SMB.Core_Wire.Initialize_Header
        (Packet, SMB.Core_Wire.Command_Code (Command), Message,
         Expected.Tree_Id, Expected.Session_Id, 1, Wire_Status);
      if Wire_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "cannot build SMB header";
      end if;
      if Sign_Request then
         SMB.Core_Wire.Write_U32 (Packet, 16, 8, Wire_Status);
      end if;
      Copy_Bytes (Packet, SMB.Core_Wire.Header_Size, Payload);
      if Sign_Request then
         SMB.Core_Wire.Sign
           (Packet, SMB.Engine.Current_Signing_Key (Client.Engine_Core),
            Wire_Status);
      end if;
      if Wire_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "cannot sign SMB request";
      end if;
      SMB.Transport.Send_Frame (Client.Channel, Packet);
      declare
         Response : constant SMB.Bytes :=
           SMB.Transport.Receive_Frame (Client.Channel);
      begin
         SMB.Engine.Accept_Response
           (Client.Engine_Core, Response, Nt_Status, Engine_Status);
         if Engine_Status /= SMB.Ok then
            if Command = SMB.Wire.Session_Setup_Command
              and then Require_Signed_Response
            then
               raise SMB.Authentication_Error with
                 "server did not complete signed SMB authentication";
            end if;
            raise SMB.Protocol_Error with
              "SMB response rejected by session engine: "
              & SMB.Core_Status'Image (Engine_Status);
         end if;
         Client.Last_Status := Nt_Status;
         return Response;
      end;
      end;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
         then
            Clear_State (Client);
            raise;
         elsif Ada.Exceptions.Exception_Identity (E) = SMB.Invalid_State'Identity
         then
            raise;
         else
            Clear_State (Client);
            raise SMB.Protocol_Error with Ada.Exceptions.Exception_Message (E);
         end if;
   end Exchange;

   procedure Check_Handle
     (Client : Connection;
      File : Handle;
      Require_Read, Require_Write : Boolean;
      File_Id : out SMB.Bytes;
      Directory : out Boolean) is
      Handle_Access : SMB.Engine.Access_Kind;
      Status : SMB.Core_Status;
   begin
      File_Id := (others => 0);
      Directory := False;
      SMB.Engine.Validate_Handle
        (Client.Engine_Core, File.Engine_Token, Require_Read, Require_Write,
         File_Id, Handle_Access, Directory, Status);
      if Status /= SMB.Ok then
         raise SMB.Invalid_State with
           "SMB handle rejected by session engine: "
           & SMB.Core_Status'Image (Status);
      end if;
   end Check_Handle;

   function Validated_Path (Path : String; Allow_Empty : Boolean := False)
                           return String is
   begin
      if Path'Length > SMB.Core_Protocol.Maximum_Name_Bytes then
         raise SMB.Protocol_Error with "SMB path exceeds protocol limit";
      end if;
      declare
         Result : String (Path'Range);
         Text_Status : SMB.Core_Status;
      begin
         SMB.Core_Text.Validate_Path
           (Path, Result, Allow_Empty, Text_Status);
         if Text_Status /= SMB.Ok then
            raise SMB.Protocol_Error with "invalid SMB relative path";
         end if;
         return Result;
      end;
   end Validated_Path;

   function Encode_Name (Value : String) return SMB.Bytes is
      Used : Natural;
      Text_Status : SMB.Core_Status;
   begin
      if Value'Length > SMB.Core_Protocol.Maximum_Name_Bytes then
         raise SMB.Protocol_Error with "SMB name exceeds frame limit";
      end if;
      if Value'Length = 0 then
         return SMB.Bytes'(1 .. 0 => 0);
      end if;
      declare
         Result : SMB.Bytes
           (0 .. SMB.Core_Protocol.Maximum_Name_Bytes - 1) := (others => 0);
      begin
         SMB.Core_Text.UTF8_To_UTF16
           (Value, Result, Used, Text_Status);
         if Text_Status /= SMB.Ok
           or else Used > SMB.Core_Protocol.Maximum_Name_Bytes
         then
            raise SMB.Protocol_Error with "SMB name exceeds protocol limit";
         end if;
         return Result (0 .. Used - 1);
      end;
   end Encode_Name;

   function Decode_Name (Value : SMB.Bytes) return String is
      Output : String (1 .. 2 * Value'Length);
      Used : Natural;
      Text_Status : SMB.Core_Status;
   begin
      SMB.Core_Text.UTF16_To_UTF8 (Value, Output, Used, Text_Status);
      if Text_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "invalid SMB directory name encoding";
      end if;
      if Used = 0 then
         return "";
      end if;
      return Output (1 .. Used);
   end Decode_Name;

   function Disposition_Value (Value : Create_Disposition) return SMB.DWord is
     (case Value is
        when Open_Existing => 1,
        when Create_New => 2,
        when Open_Or_Create => 3,
        when Truncate_Existing => 4,
        when Create_Or_Truncate => 5);

   function Create_Internal
     (Client : in out Connection;
      Path : String;
      Mode : Access_Mode;
      Disposition : Create_Disposition;
      Is_Directory : Boolean;
      Additional_Access : SMB.DWord := 0) return Handle is
      UTF16_Name : constant SMB.Bytes := Encode_Name (Path);
      Packet : SMB.Bytes
        (0 .. SMB.Core_Wire.Header_Size + 56
          + Natural'Max (1, UTF16_Name'Length) - 1) := (others => 0);
      Used : Natural;
      Token : SMB.Engine.Handle_Token;
      Core_Status : SMB.Core_Status;
      Operation : SMB.Core_Client.Operation;
      Engine_Access : constant SMB.Engine.Access_Kind :=
        (case Mode is
           when Read_Only => SMB.Engine.Read_Only,
           when Write_Only => SMB.Engine.Write_Only,
           when Read_Write => SMB.Engine.Read_Write);
   begin
      if Additional_Access /= 0 and then Additional_Access /= File_Delete then
         raise SMB.Protocol_Error with "unsupported SMB CREATE access extension";
      end if;
      SMB.Core_Client.Prepare_Create
        (Operation, Client.Engine_Core, UTF16_Name, Engine_Access,
         Additional_Access = File_Delete, Disposition_Value (Disposition),
         Is_Directory, Packet, Used, Core_Status);
      if Core_Status /= SMB.Ok then
         if Core_Status = SMB.Invalid_State_Status then
            raise SMB.Invalid_State with "SMB CREATE is not valid in this state";
         end if;
         raise SMB.Protocol_Error with "SMB CREATE request exceeds limits";
      end if;
      SMB.Transport.Send_Frame (Client.Channel, Packet (0 .. Used - 1));
      SMB.Core_Client.Send_Succeeded
        (Operation, Client.Engine_Core, Core_Status);
      if Core_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "SMB CREATE send was not acknowledged";
      end if;
      declare
         Response : constant SMB.Bytes :=
           SMB.Transport.Receive_Frame (Client.Channel);
      begin
         SMB.Core_Client.Complete
           (Operation, Client.Engine_Core, Response, Client.Last_Status,
            Token, Core_Status);
         if Core_Status /= SMB.Ok then
            raise SMB.Protocol_Error with "SMB CREATE response was rejected";
         end if;
         Require_Status (Client, Client.Last_Status);
      end;
      return Result : Handle do
         Result.Engine_Token := Token;
      end return;
   exception
      when others =>
         if SMB.Core_Client.Stage_Of (Operation) = SMB.Core_Client.Prepared
           or else SMB.Core_Client.Stage_Of (Operation) =
             SMB.Core_Client.Sent
         then
            SMB.Core_Client.Abort_Operation
              (Operation, Client.Engine_Core, Core_Status);
         end if;
         if SMB.Engine.Current_Phase (Client.Engine_Core) =
           SMB.Engine.Disconnected
         then
            Clear_State_Preserving_Status (Client);
         end if;
         raise;
   end Create_Internal;

   procedure Close_Internal (Client : in out Connection; File : in out Handle) is
      Packet : SMB.Bytes (0 .. SMB.Core_Wire.Header_Size + 24 - 1) :=
        (others => 0);
      Used : Natural;
      Core_Status : SMB.Core_Status;
      Operation : SMB.Core_Client.Operation;
   begin
      SMB.Core_Client.Prepare_Close
        (Operation, Client.Engine_Core, File.Engine_Token,
         Packet, Used, Core_Status);
      if Core_Status /= SMB.Ok then
         raise SMB.Invalid_State with "SMB handle rejected for CLOSE";
      end if;
      SMB.Transport.Send_Frame (Client.Channel, Packet (0 .. Used - 1));
      SMB.Core_Client.Send_Succeeded
        (Operation, Client.Engine_Core, Core_Status);
      if Core_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "SMB CLOSE send was not acknowledged";
      end if;
      declare
         Response : constant SMB.Bytes :=
           SMB.Transport.Receive_Frame (Client.Channel);
      begin
         declare
            Ignored_Token : SMB.Engine.Handle_Token;
         begin
            SMB.Core_Client.Complete
              (Operation, Client.Engine_Core, Response, Client.Last_Status,
               Ignored_Token, Core_Status);
         end;
         if Core_Status /= SMB.Ok then
            raise SMB.Protocol_Error with "SMB CLOSE response was rejected";
         end if;
         Require_Status (Client, Client.Last_Status);
      end;
      File.Engine_Token := (others => 0);
   exception
      when others =>
         if SMB.Core_Client.Stage_Of (Operation) = SMB.Core_Client.Prepared
           or else SMB.Core_Client.Stage_Of (Operation) =
             SMB.Core_Client.Sent
         then
            SMB.Core_Client.Abort_Operation
              (Operation, Client.Engine_Core, Core_Status);
         end if;
         if SMB.Engine.Current_Phase (Client.Engine_Core) =
           SMB.Engine.Disconnected
         then
            Clear_State_Preserving_Status (Client);
         end if;
         raise;
   end Close_Internal;

   procedure Cleanup_Close
     (Client : in out Connection;
      File : in out Handle;
      Original_Status : SMB.DWord) is
   begin
      begin
         Close_Internal (Client, File);
      exception
         when others =>
            Clear_State (Client);
      end;
      Client.Last_Status := Original_Status;
   end Cleanup_Close;

   procedure Set_Disposition
     (Client : in out Connection; File : Handle; Delete_File : Boolean) is
      Payload : SMB.Bytes (0 .. 32) := (others => 0);
      File_Id : SMB.Bytes (0 .. 15);
      Directory : Boolean;
      Used : Natural;
      Build_Status : SMB.Core_Status;
   begin
      Check_Handle (Client, File, False, False, File_Id, Directory);
      SMB.Core_Protocol.Build_Disposition
        (File_Id, Delete_File, Payload, Used, Build_Status);
      if Build_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "cannot build SMB disposition request";
      end if;
      declare
         Response : constant SMB.Bytes := Exchange
           (Client, SMB.Wire.Set_Info_Command, Payload (0 .. Used - 1),
            Sign_Request => True, Require_Signed_Response => True,
            Request_Session => Session_Identifier (Client),
            Response_Session => Session_Identifier (Client),
            Request_Tree => Tree_Identifier (Client),
            Response_Tree => Tree_Identifier (Client));
      begin
         pragma Unreferenced (Response);
         Require_Status (Client, Client.Last_Status);
      end;
   end Set_Disposition;

   procedure Require_Relative_Share (Share : String) is
      Status : SMB.Core_Status;
   begin
      if Share'Length = 0 or else Share'Length > 255 then
         raise SMB.Protocol_Error with "invalid SMB share name";
      end if;
      SMB.Core_Text.Validate_Share (Share, Status);
      if Status /= SMB.Ok then
         raise SMB.Protocol_Error with "invalid SMB share name";
      end if;
   end Require_Relative_Share;

   procedure Connect
     (Client : in out Connection;
      Host : String;
      Port : Positive := 445;
      Timeout_Seconds : Duration := 10.0;
      Entropy : Entropy_Source := null) is
      Guid : SMB.Bytes (0 .. 15);
      Payload : SMB.Bytes (0 .. 37) := (others => 0);
      Used : Natural;
      Engine_Status : SMB.Core_Status;
      Response_Info : SMB.Core_Protocol.Response_Info;
   begin
      SMB.Engine.Initialize (Client.Engine_Core, Engine_Status);
      if Engine_Status /= SMB.Ok then
         raise SMB.Invalid_State with
           "session engine rejected initialization: "
           & SMB.Core_Status'Image (Engine_Status);
      end if;
      Client.Entropy := Entropy;
      Get_Entropy (Client, Guid);
      SMB.Transport.Connect
        (Client.Channel, Host, Port, Timeout_Seconds);
      Client.Host := Ada.Strings.Unbounded.To_Unbounded_String (Host);
      SMB.Engine.Mark_Connected (Client.Engine_Core, Engine_Status);
      if Engine_Status /= SMB.Ok then
         raise SMB.Invalid_State with "session engine rejected transport connection";
      end if;
      SMB.Core_Protocol.Build_Negotiate
        (Guid, Payload, Used, Engine_Status);
      if Engine_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "cannot build SMB negotiate request";
      end if;
      declare
         Response : constant SMB.Bytes := Exchange
           (Client, SMB.Wire.Negotiate_Command, Payload (0 .. Used - 1));
      begin
         pragma Unreferenced (Response);
      end;
      Require_Status (Client, Client.Last_Status);
      Response_Info := SMB.Engine.Current_Response_Info (Client.Engine_Core);
      SMB.Engine.Mark_Negotiated
        (Client.Engine_Core, Response_Info.Max_Read, Response_Info.Max_Write,
         Engine_Status);
      if Engine_Status /= SMB.Ok then
         Clear_State (Client);
         raise SMB.Protocol_Error with "invalid negotiated SMB limits";
      end if;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Invalid_State'Identity
         then
            raise;
         end if;
         if Ada.Exceptions.Exception_Identity (E) = SMB.NT_Status_Error'Identity
         then
            Clear_State_Preserving_Status (Client);
         else
            Clear_State (Client);
         end if;
         if Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
         then
            raise;
         end if;
         raise SMB.Protocol_Error with Ada.Exceptions.Exception_Message (E);
   end Connect;

   procedure Authenticate
     (Client : in out Connection;
      User, Password : String;
      Domain : String := "") is
      Initial_Token : constant SMB.Bytes := SMB.NTLM.Negotiate_Token;
      First_Body : SMB.Bytes (0 .. 23 + Initial_Token'Length) :=
        (others => 0);
      First_Used : Natural;
      Engine_Status : SMB.Core_Status;
   begin
      SMB.Core_Protocol.Build_Session_Setup
        (Initial_Token, First_Body, First_Used, Engine_Status);
      if Engine_Status /= SMB.Ok then
         raise SMB.Authentication_Error with "initial SMB token exceeds limits";
      end if;
      declare
         First_Response : constant SMB.Bytes := Exchange
           (Client, SMB.Wire.Session_Setup_Command,
            First_Body (0 .. First_Used - 1),
            Request_Session => 0, Response_Session => 0);
      begin
         if Client.Last_Status /= SMB.Status_More_Processing_Required then
            Require_Status (Client, Client.Last_Status);
            raise SMB.Authentication_Error with
              "server did not issue an NTLM challenge";
         end if;
         declare
            Response_Info : constant SMB.Core_Protocol.Response_Info :=
              SMB.Engine.Current_Response_Info (Client.Engine_Core);
            Challenge_Session_Id : constant SMB.QWord :=
              Response_Info.Session_Id;
         begin
            declare
               Challenge_Token : constant SMB.Bytes :=
                 Slice (First_Response, Response_Info.Data_Offset,
                        Response_Info.Data_Length);
               Nonce : SMB.Bytes (0 .. 7);
            begin
               Get_Entropy (Client, Nonce);
               declare
                  Auth : constant SMB.NTLM.Authentication_Result :=
                    SMB.NTLM.Authenticate
                      (User, Password, Domain, Nonce, Challenge_Token,
                       SMB.Clock.Current_Filetime);
                  Second_Body : SMB.Bytes
                    (0 .. 23 + Auth.Security_Token'Length) := (others => 0);
                  Second_Used : Natural;
               begin
                  SMB.Core_Protocol.Build_Session_Setup
                    (Auth.Security_Token, Second_Body, Second_Used,
                     Engine_Status);
                  if Engine_Status /= SMB.Ok then
                     raise SMB.Authentication_Error with
                       "authenticated SMB token exceeds limits";
                  end if;
                  SMB.Engine.Install_Session_Key
                    (Client.Engine_Core, Challenge_Session_Id,
                     Auth.Session_Key, Engine_Status);
                  if Engine_Status /= SMB.Ok then
                     raise SMB.Authentication_Error with
                       "session engine rejected authenticated session key";
                  end if;
                  declare
                     Second_Response : constant SMB.Bytes := Exchange
                       (Client, SMB.Wire.Session_Setup_Command,
                        Second_Body (0 .. Second_Used - 1),
                        Sign_Request => False, Require_Signed_Response => True,
                        Request_Session => Session_Identifier (Client),
                        Response_Session => Session_Identifier (Client));
                  begin
                     pragma Unreferenced (Second_Response);
                     Require_Status (Client, Client.Last_Status);
                  end;
               end;
            end;
         end;
      end;
      SMB.Engine.Mark_Authenticated (Client.Engine_Core, Engine_Status);
      if Engine_Status /= SMB.Ok then
         raise SMB.Authentication_Error with
           "session engine rejected authenticated session state";
      end if;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Invalid_State'Identity
         then
            raise;
         end if;
         if Ada.Exceptions.Exception_Identity (E) = SMB.NT_Status_Error'Identity
         then
            Clear_State_Preserving_Status (Client);
         else
            Clear_State (Client);
         end if;
         if Ada.Exceptions.Exception_Identity (E) = SMB.NT_Status_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
         then
            raise;
         end if;
         raise SMB.Authentication_Error with Ada.Exceptions.Exception_Message (E);
   end Authenticate;

   procedure Connect_Share (Client : in out Connection; Share : String) is
   begin
      Require_Relative_Share (Share);
      declare
         UNC : constant String :=
           "\\" & Ada.Strings.Unbounded.To_String (Client.Host) & "\" & Share;
         Name : constant SMB.Bytes := Encode_Name (UNC);
         Payload : SMB.Bytes (0 .. 7 + Name'Length) := (others => 0);
         Used : Natural;
         Engine_Status : SMB.Core_Status;
      begin
      SMB.Core_Protocol.Build_Tree_Connect
        (Name, Payload, Used, Engine_Status);
      if Engine_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "share name exceeds SMB limits";
      end if;
      declare
         Response : constant SMB.Bytes := Exchange
           (Client, SMB.Wire.Tree_Connect_Command, Payload (0 .. Used - 1),
            Sign_Request => True, Require_Signed_Response => True,
            Request_Session => Session_Identifier (Client),
            Response_Session => Session_Identifier (Client));
      begin
         pragma Unreferenced (Response);
      end;
      Require_Status (Client, Client.Last_Status);
      declare
         Response_Info : constant SMB.Core_Protocol.Response_Info :=
           SMB.Engine.Current_Response_Info (Client.Engine_Core);
      begin
         SMB.Engine.Mark_Share_Connected
           (Client.Engine_Core, Response_Info.Tree_Id, Engine_Status);
      end;
      if Engine_Status /= SMB.Ok then
         Clear_State (Client);
         raise SMB.Protocol_Error with "session engine rejected share connection";
      end if;
      end;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
         then
            Clear_State (Client);
         end if;
         raise;
   end Connect_Share;

   function Open_File
     (Client : in out Connection;
      Path : String;
      Mode : Access_Mode := Read_Only;
      Disposition : Create_Disposition := Open_Existing) return Handle is
      Safe_Path : constant String := Validated_Path (Path);
   begin
      return Create_Internal
        (Client, Safe_Path, Mode, Disposition, False);
   end Open_File;

   function Read
     (Client : in out Connection;
      File : Handle;
      Offset : SMB.QWord;
      Length : Positive) return SMB.Bytes is
      function Checked_Length return Natural is
      begin
         if Length > SMB.Maximum_Frame_Size then
            raise SMB.Protocol_Error with "invalid SMB read request";
         end if;
         return Length;
      end Checked_Length;
      Output : SMB.Bytes (0 .. Checked_Length - 1);
      Position : SMB.QWord := Offset;
      Remaining : Natural := Length;
      File_Id : SMB.Bytes (0 .. 15);
      Directory : Boolean;
      Core_Status : SMB.Core_Status;
   begin
      Check_Handle (Client, File, True, False, File_Id, Directory);
      if Directory then
         raise SMB.Protocol_Error with "invalid SMB read request";
      end if;
      SMB.Core_Protocol.Check_Transfer_Range (Offset, Length, Core_Status);
      if Core_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "SMB read offset overflow";
      end if;
      while Remaining > 0 loop
         declare
            Amount : Natural;
            Payload : SMB.Bytes (0 .. 48) := (others => 0);
            Used : Natural;
         begin
            SMB.Core_Protocol.Select_Transfer_Amount
              (Remaining, Read_Limit (Client), Amount, Core_Status);
            if Core_Status /= SMB.Ok then
               raise SMB.Protocol_Error with "invalid SMB read limit";
            end if;
            SMB.Core_Protocol.Build_Read
              (File_Id, Position, Amount, Payload, Used, Core_Status);
            if Core_Status /= SMB.Ok or else Amount = 0 then
               raise SMB.Protocol_Error with "invalid SMB READ request bounds";
            end if;
            declare
               Response : constant SMB.Bytes := Exchange
                 (Client, SMB.Wire.Read_Command, Payload (0 .. Used - 1),
                  Sign_Request => True, Require_Signed_Response => True,
                  Request_Session => Session_Identifier (Client),
                  Response_Session => Session_Identifier (Client),
                  Request_Tree => Tree_Identifier (Client),
                  Response_Tree => Tree_Identifier (Client),
                  Request_Amount => Amount);
            begin
               if Client.Last_Status = SMB.Status_End_Of_File then
                  exit;
               end if;
               Require_Status (Client, Client.Last_Status);
               declare
                  Info : constant SMB.Core_Protocol.Response_Info :=
                    SMB.Engine.Current_Response_Info (Client.Engine_Core);
                  Completed : constant Natural := Length - Remaining;
               begin
                  Copy_Bytes
                    (Output, Completed,
                     Slice (Response, Info.Data_Offset, Info.Data_Length));
                  SMB.Core_Protocol.Advance_Transfer
                    (Position, Remaining, Amount, Info.Data_Length,
                     Core_Status, Require_Progress => False);
                  if Core_Status /= SMB.Ok then
                     raise SMB.Protocol_Error with "invalid SMB read progress";
                  end if;
                  if Info.Data_Length = 0 or else Info.Data_Length < Amount then
                     exit;
                  end if;
               end;
            end;
         end;
      end loop;
      declare
         Completed : constant Natural := Length - Remaining;
      begin
      if Completed = 0 then
         return SMB.Bytes'(1 .. 0 => 0);
      end if;
      return Output (0 .. Completed - 1);
      end;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
         then
            Clear_State (Client);
         end if;
         raise;
   end Read;

   procedure Write
     (Client : in out Connection;
      File : Handle;
      Offset : SMB.QWord;
      Data : SMB.Bytes) is
      Position : SMB.QWord := Offset;
      Remaining : Natural := Data'Length;
      File_Id : SMB.Bytes (0 .. 15);
      Directory : Boolean;
      Core_Status : SMB.Core_Status;
   begin
      Check_Handle (Client, File, False, True, File_Id, Directory);
      if Directory or else Data'Length > SMB.Maximum_Frame_Size then
         raise SMB.Protocol_Error with "invalid SMB write request";
      end if;
      SMB.Core_Protocol.Check_Transfer_Range
        (Offset, Data'Length, Core_Status);
      if Core_Status /= SMB.Ok then
         raise SMB.Protocol_Error with "SMB write offset overflow";
      end if;
      while Remaining > 0 loop
         declare
            Amount : Natural;
         begin
            SMB.Core_Protocol.Select_Transfer_Amount
              (Remaining, Write_Limit (Client), Amount, Core_Status);
            if Core_Status /= SMB.Ok then
               raise SMB.Protocol_Error with "invalid SMB write limit";
            end if;
            declare
               Sent : constant Natural := Data'Length - Remaining;
               Payload : SMB.Bytes (0 .. 47 + Amount) := (others => 0);
               Used : Natural;
            begin
               SMB.Core_Protocol.Build_Write
                 (File_Id, Position, Slice (Data, Sent, Amount),
                  Payload, Used, Core_Status);
               if Core_Status /= SMB.Ok then
                  raise SMB.Protocol_Error with
                    "cannot build SMB WRITE request";
               end if;
               declare
                  Response : constant SMB.Bytes := Exchange
                    (Client, SMB.Wire.Write_Command,
                     Payload (0 .. Used - 1),
                     Sign_Request => True, Require_Signed_Response => True,
                     Request_Session => Session_Identifier (Client),
                     Response_Session => Session_Identifier (Client),
                     Request_Tree => Tree_Identifier (Client),
                     Response_Tree => Tree_Identifier (Client),
                     Request_Amount => Amount);
               begin
                  pragma Unreferenced (Response);
                  Require_Status (Client, Client.Last_Status);
                  declare
                     Info : constant SMB.Core_Protocol.Response_Info :=
                       SMB.Engine.Current_Response_Info (Client.Engine_Core);
                  begin
                     SMB.Core_Protocol.Advance_Transfer
                       (Position, Remaining, Amount, Info.Count, Core_Status);
                     if Core_Status /= SMB.Ok then
                        raise SMB.Protocol_Error with
                          "invalid SMB write progress";
                     end if;
                  end;
               end;
            end;
         end;
      end loop;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
         then
            Clear_State (Client);
         end if;
         raise;
   end Write;

   procedure Close (Client : in out Connection; File : in out Handle) is
      File_Id : SMB.Bytes (0 .. 15);
      Directory : Boolean;
   begin
      Check_Handle (Client, File, False, False, File_Id, Directory);
      Close_Internal (Client, File);
   end Close;

   function List_Directory
     (Client : in out Connection;
      Path : String := "") return Directory_Entry_Array is
      Safe_Path : constant String := Validated_Path (Path, Allow_Empty => True);
      Entries : Entry_Vectors.Vector;
      Finished : Boolean := False;
      Restart : Boolean := True;
      Page_Count : Natural := 0;
      Entry_Count : Natural := 0;
      Core_Status : SMB.Core_Status;
   begin
      declare
         Folder : Handle := Create_Internal
           (Client, Safe_Path, Read_Only, Open_Existing, True);
         Folder_Id : SMB.Bytes (0 .. 15);
         Is_Directory : Boolean;
      begin
       Check_Handle (Client, Folder, False, False, Folder_Id, Is_Directory);
       pragma Unreferenced (Is_Directory);
       while not Finished loop
         SMB.Core_Protocol.Count_Directory_Page (Page_Count, Core_Status);
         if Core_Status /= SMB.Ok then
            raise SMB.Protocol_Error with "SMB directory pagination limit exceeded";
         end if;
         declare
            Payload : SMB.Bytes (0 .. 33) := (others => 0);
            Used : Natural;
         begin
            SMB.Core_Protocol.Build_Query_Directory
              (Folder_Id, Restart, Payload, Used, Core_Status);
            if Core_Status /= SMB.Ok then
               raise SMB.Protocol_Error with "cannot build SMB directory query";
            end if;
            declare
               Response : constant SMB.Bytes := Exchange
                 (Client, SMB.Wire.Query_Directory_Command,
                  Payload (0 .. Used - 1),
                  Sign_Request => True, Require_Signed_Response => True,
                  Request_Session => Session_Identifier (Client),
                  Response_Session => Session_Identifier (Client),
                  Request_Tree => Tree_Identifier (Client),
                  Response_Tree => Tree_Identifier (Client),
                  Request_Amount => SMB.Core_Protocol.Maximum_IO_Chunk);
            begin
               Restart := False;
               if Client.Last_Status = SMB.Status_No_More_Files then
                  Finished := True;
               else
                  Require_Status (Client, Client.Last_Status);
                  declare
                     Response_Info : constant SMB.Core_Protocol.Response_Info :=
                       SMB.Engine.Current_Response_Info (Client.Engine_Core);
                     Data : constant SMB.Bytes :=
                       Slice (Response, Response_Info.Data_Offset,
                              Response_Info.Data_Length);
                     Cursor : Natural := 0;
                  begin
                     while Cursor < Data'Length loop
                        declare
                           Entry_Info : SMB.Core_Protocol.Directory_Info;
                           Item : Directory_Entry;
                        begin
                           SMB.Core_Protocol.Parse_Directory_Entry
                             (Data, Cursor, Entry_Info, Core_Status);
                           if Core_Status /= SMB.Ok then
                              raise SMB.Protocol_Error with
                                "malformed SMB directory entry";
                           end if;
                           SMB.Core_Protocol.Count_Directory_Entry
                             (Entry_Count, Core_Status);
                           if Core_Status /= SMB.Ok then
                              raise SMB.Protocol_Error with
                                "directory entry limit exceeded";
                           end if;
                           declare
                              Name : constant String := Decode_Name
                                (Slice (Data, Entry_Info.Name_Offset,
                                        Entry_Info.Name_Length));
                           begin
                              if Name /= "." and then Name /= ".." then
                                 Item.Name :=
                                   Ada.Strings.Unbounded.To_Unbounded_String (Name);
                                 Item.Size := Entry_Info.Size;
                                 Item.Attributes := Entry_Info.Attributes;
                                 Entries.Append (Item);
                              end if;
                           end;
                        end;
                     end loop;
                     if Data'Length = 0 then
                        Finished := True;
                     end if;
                  end;
               end if;
            end;
         end;
       end loop;
       Close_Internal (Client, Folder);
       exception
         when others =>
            if Folder.Engine_Token.Ticket /= 0
              and then SMB.Engine.Current_Phase (Client.Engine_Core) =
                Share_Connected
            then
               declare
                  Original_Status : constant SMB.DWord := Client.Last_Status;
               begin
                  Cleanup_Close (Client, Folder, Original_Status);
               end;
            end if;
            raise;
      end;
      declare
         Count : constant Natural := Natural (Entries.Length);
      begin
         if Count = 0 then
            return Directory_Entry_Array'(1 .. 0 => <>);
         end if;
         declare
            Result : Directory_Entry_Array (1 .. Count);
         begin
            for I in 1 .. Count loop
               Result (I) := Entries.Element (I - 1);
            end loop;
            return Result;
         end;
      end;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
         then
            Clear_State (Client);
         end if;
         raise;
   end List_Directory;

   procedure Make_Directory (Client : in out Connection; Path : String) is
      Safe_Path : constant String := Validated_Path (Path);
   begin
      declare
         Folder : Handle :=
           Create_Internal (Client, Safe_Path, Read_Write, Create_New, True);
      begin
         Close_Internal (Client, Folder);
         exception
         when others =>
            if Folder.Engine_Token.Ticket /= 0
              and then SMB.Engine.Current_Phase (Client.Engine_Core) =
                Share_Connected
            then
               declare
                  Original_Status : constant SMB.DWord := Client.Last_Status;
               begin
                  Cleanup_Close (Client, Folder, Original_Status);
               end;
            end if;
            raise;
      end;
   end Make_Directory;

   procedure Remove_File (Client : in out Connection; Path : String) is
      Safe_Path : constant String := Validated_Path (Path);
   begin
      declare
         File : Handle := Create_Internal
           (Client, Safe_Path, Read_Only, Open_Existing, False, File_Delete);
      begin
         Set_Disposition (Client, File, True);
         Close_Internal (Client, File);
         exception
         when others =>
            if File.Engine_Token.Ticket /= 0
              and then SMB.Engine.Current_Phase (Client.Engine_Core) =
                Share_Connected
            then
               declare
                  Original_Status : constant SMB.DWord := Client.Last_Status;
               begin
                  Cleanup_Close (Client, File, Original_Status);
               end;
            end if;
            raise;
      end;
   end Remove_File;

   procedure Remove_Directory (Client : in out Connection; Path : String) is
      Safe_Path : constant String := Validated_Path (Path);
   begin
      declare
         Folder : Handle := Create_Internal
           (Client, Safe_Path, Read_Only, Open_Existing, True, File_Delete);
      begin
         Set_Disposition (Client, Folder, True);
         Close_Internal (Client, Folder);
         exception
         when others =>
            if Folder.Engine_Token.Ticket /= 0
              and then SMB.Engine.Current_Phase (Client.Engine_Core) =
                Share_Connected
            then
               declare
                  Original_Status : constant SMB.DWord := Client.Last_Status;
               begin
                  Cleanup_Close (Client, Folder, Original_Status);
               end;
            end if;
            raise;
      end;
   end Remove_Directory;

   procedure Rename (Client : in out Connection; Old_Path, New_Path : String) is
      Old_Name : constant String := Validated_Path (Old_Path);
      New_Name : constant String := Validated_Path (New_Path);
      New_UTF16 : constant SMB.Bytes := Encode_Name (New_Name);
   begin
      declare
         File : Handle := Create_Internal
           (Client, Old_Name, Read_Only, Open_Existing, False, File_Delete);
         Payload : SMB.Bytes (0 .. 51 + New_UTF16'Length) := (others => 0);
         File_Id : SMB.Bytes (0 .. 15);
         Directory : Boolean;
         Used : Natural;
         Build_Status : SMB.Core_Status;
      begin
         Check_Handle (Client, File, False, False, File_Id, Directory);
         SMB.Core_Protocol.Build_Rename
           (File_Id, New_UTF16, Payload, Used, Build_Status);
         if Build_Status /= SMB.Ok then
            raise SMB.Protocol_Error with "cannot build SMB rename request";
         end if;
         declare
            Response : constant SMB.Bytes := Exchange
              (Client, SMB.Wire.Set_Info_Command, Payload (0 .. Used - 1),
               Sign_Request => True, Require_Signed_Response => True,
               Request_Session => Session_Identifier (Client),
               Response_Session => Session_Identifier (Client),
               Request_Tree => Tree_Identifier (Client),
               Response_Tree => Tree_Identifier (Client));
          begin
            pragma Unreferenced (Response);
            Require_Status (Client, Client.Last_Status);
         end;
         Close_Internal (Client, File);
      exception
         when others =>
            if File.Engine_Token.Ticket /= 0
              and then SMB.Engine.Current_Phase (Client.Engine_Core) =
                Share_Connected
            then
               declare
                  Original_Status : constant SMB.DWord := Client.Last_Status;
               begin
                  Cleanup_Close (Client, File, Original_Status);
               end;
            end if;
            raise;
      end;
   exception
      when E : others =>
         if Ada.Exceptions.Exception_Identity (E) = SMB.Protocol_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Transport_Error'Identity
           or else Ada.Exceptions.Exception_Identity (E) = SMB.Authentication_Error'Identity
         then
            Clear_State (Client);
         end if;
         raise;
   end Rename;

   procedure Disconnect (Client : in out Connection) is
      Payload : SMB.Bytes (0 .. 3) := (others => 0);
      Used : Natural;
      Build_Status : SMB.Core_Status;
      First_Error : Ada.Exceptions.Exception_Occurrence;
      Has_Error : Boolean := False;
      First_Status : SMB.DWord := SMB.Success;
   begin
      if SMB.Engine.Current_Phase (Client.Engine_Core) = Share_Connected then
         begin
            SMB.Core_Protocol.Build_Simple (Payload, Used, Build_Status);
            if Build_Status /= SMB.Ok then
               raise SMB.Protocol_Error with "cannot build tree disconnect request";
            end if;
            declare
               Response : constant SMB.Bytes := Exchange
                 (Client, SMB.Wire.Tree_Disconnect_Command,
                  Payload (0 .. Used - 1),
                  Sign_Request => True, Require_Signed_Response => True,
                  Request_Session => Session_Identifier (Client),
                  Response_Session => Session_Identifier (Client),
                  Request_Tree => Tree_Identifier (Client),
                  Response_Tree => Tree_Identifier (Client));
            begin
               pragma Unreferenced (Response);
               Require_Status (Client, Client.Last_Status);
            end;
         exception
            when E : others =>
               if not Has_Error then
                  Ada.Exceptions.Save_Occurrence (First_Error, E);
                  First_Status := Client.Last_Status;
                  Has_Error := True;
               end if;
         end;
      end if;
      if SMB.Engine.Current_Phase (Client.Engine_Core) in
        Authenticated | Share_Connected
      then
         begin
            SMB.Core_Protocol.Build_Simple (Payload, Used, Build_Status);
            if Build_Status /= SMB.Ok then
               raise SMB.Protocol_Error with "cannot build logoff request";
            end if;
            declare
               Response : constant SMB.Bytes := Exchange
                 (Client, SMB.Wire.Logoff_Command, Payload (0 .. Used - 1),
                  Sign_Request => True, Require_Signed_Response => True,
                  Request_Session => Session_Identifier (Client),
                  Response_Session => Session_Identifier (Client));
            begin
               pragma Unreferenced (Response);
               Require_Status (Client, Client.Last_Status);
            end;
         exception
            when E : others =>
               if not Has_Error then
                  Ada.Exceptions.Save_Occurrence (First_Error, E);
                  First_Status := Client.Last_Status;
                  Has_Error := True;
               end if;
         end;
      end if;
      Clear_State (Client);
      if Has_Error then
         Client.Last_Status := First_Status;
         Ada.Exceptions.Reraise_Occurrence (First_Error);
      end if;
   end Disconnect;

   function Last_NT_Status (Client : Connection) return SMB.DWord is
     (Client.Last_Status);

   function Is_Connected (Client : Connection) return Boolean is
     (SMB.Engine.Current_Phase (Client.Engine_Core) /= Disconnected);

   overriding procedure Finalize (Client : in out Connection) is
   begin
      Disconnect (Client);
   exception
      when others => null;
   end Finalize;
end SMB.Client;
