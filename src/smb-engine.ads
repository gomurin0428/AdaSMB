with SMB.Core_Wire;
with SMB.Core_Protocol;

package SMB.Engine
  with SPARK_Mode,
       Abstract_State => Identity_Registry,
       Initializes => Identity_Registry
is
   use type SMB.Byte;
   use type SMB.Core_Wire.Command_Code;
   use type SMB.DWord;
   use type SMB.QWord;

   Maximum_Handles : constant := 256;

   type Phase is
     (Disconnected, Transport_Connected, Negotiated, Authenticated,
      Share_Connected);
   type Access_Kind is (Read_Only, Write_Only, Read_Write);

   type Handle_Token is record
      Owner : SMB.QWord := 0;
      Epoch : SMB.QWord := 0;
      Ticket : SMB.QWord := 0;
   end record;

   type Request_Expectation is record
      Command : SMB.Core_Wire.Command_Code := 0;
      Message_Id : SMB.QWord := 0;
      Tree_Id : SMB.DWord := 0;
      Session_Id : SMB.QWord := 0;
      Match_Tree : Boolean := False;
      Match_Session : Boolean := False;
      Request_Signed : Boolean := False;
      Signed : Boolean := False;
      Request_Amount : Natural := 0;
      Close_Token : Handle_Token := (others => 0);
   end record;

   type Engine_State is private;

   function Handle_Table_Equivalent
     (Left, Right : Engine_State) return Boolean
   with Ghost;

   function Other_Handles_Preserved
     (Left, Right : Engine_State;
      Except_Ticket : SMB.QWord := 0) return Boolean
   with Ghost;

   procedure Lemma_Handle_Table_Transitive
     (First, Middle, Last : Engine_State)
   with Ghost,
     Pre => Handle_Table_Equivalent (First, Middle)
       and then Handle_Table_Equivalent (Middle, Last),
     Post => Handle_Table_Equivalent (First, Last);

   function Current_Phase (State : Engine_State) return Phase;
   function Current_Session_Id (State : Engine_State) return SMB.QWord;
   function Current_Tree_Id (State : Engine_State) return SMB.DWord;
   function Current_Max_Read (State : Engine_State) return Natural;
   function Current_Max_Write (State : Engine_State) return Natural;
   function Current_Async_Id (State : Engine_State) return SMB.QWord;
   function Has_Open_Handles (State : Engine_State) return Boolean;
   function Has_Pending_Request (State : Engine_State) return Boolean;
   function Has_Signing_Key (State : Engine_State) return Boolean;
   function Current_Response_Info (State : Engine_State)
     return SMB.Core_Protocol.Response_Info;
   function Signing_Key_Is_Zero (State : Engine_State) return Boolean;
   function Current_Owner_Id (State : Engine_State) return SMB.QWord;
   function Current_Epoch (State : Engine_State) return SMB.QWord;
   function Connection_Context_Equivalent
     (Left, Right : Engine_State) return Boolean
   with Ghost,
     Post => Connection_Context_Equivalent'Result =
       (Current_Phase (Left) = Current_Phase (Right)
        and then Current_Owner_Id (Left) = Current_Owner_Id (Right)
        and then Current_Epoch (Left) = Current_Epoch (Right)
        and then Current_Session_Id (Left) = Current_Session_Id (Right)
        and then Current_Tree_Id (Left) = Current_Tree_Id (Right)
        and then Current_Max_Read (Left) = Current_Max_Read (Right)
        and then Current_Max_Write (Left) = Current_Max_Write (Right)
        and then Has_Signing_Key (Left) = Has_Signing_Key (Right)
        and then Current_Signing_Key (Left) = Current_Signing_Key (Right)
        and then Handle_Table_Equivalent (Left, Right));
   function Interim_Context_Equivalent
     (Left, Right : Engine_State) return Boolean
   with Ghost;
   procedure Lemma_Connection_Context_Transitive
     (First, Middle, Last : Engine_State)
   with Ghost,
     Pre => Connection_Context_Equivalent (First, Middle)
       and then Connection_Context_Equivalent (Middle, Last),
     Post => Connection_Context_Equivalent (First, Last);

   function Valid_Handle
     (State : Engine_State;
      Token : Handle_Token;
      Need_Read, Need_Write : Boolean) return Boolean
   with Ghost;
   function Handle_Matches
     (State : Engine_State;
      Token : Handle_Token;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean
   with Ghost;
   function Handle_Matches_In_States
     (Before, After : Engine_State;
      Token : Handle_Token;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean
   with
     Ghost,
     Pre => File_Id'Length = 16,
     Post =>
       Handle_Matches_In_States'Result =
         (Handle_Table_Equivalent (Before, After)
          and then Current_Phase (Before) = Current_Phase (After)
          and then Current_Owner_Id (Before) = Current_Owner_Id (After)
          and then Current_Epoch (Before) = Current_Epoch (After))
       and then
         (if Handle_Matches_In_States'Result then
            Handle_Matches
              (Before, Token, File_Id, Access_Mode, Is_Directory) =
            Handle_Matches
              (After, Token, File_Id, Access_Mode, Is_Directory));
   function Handle_Matches_Equivalent
     (State : Engine_State;
      Token : Handle_Token;
      Left_File_Id, Right_File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean) return Boolean
   with
     Ghost,
     Pre =>
       Left_File_Id'Length = 16
       and then Right_File_Id'Length = 16
       and then
         (for all Index in 0 .. 15 =>
            Left_File_Id (Left_File_Id'First + Index) =
              Right_File_Id (Right_File_Id'First + Index)),
     Post =>
       Handle_Matches_Equivalent'Result
       and then Handle_Matches
         (State, Token, Left_File_Id, Access_Mode, Is_Directory) =
       Handle_Matches
         (State, Token, Right_File_Id, Access_Mode, Is_Directory);
   function Has_Validated_Response (State : Engine_State) return Boolean;
   function Response_Receipt_Matches
     (State : Engine_State;
      Command : SMB.Core_Wire.Command_Code;
      Nt_Status : SMB.DWord;
      Signed, MIC_Valid : Boolean) return Boolean;
   function Pending_Command
     (State : Engine_State) return SMB.Core_Wire.Command_Code
   with Ghost;
   function Pending_Response_Is_Signed
     (State : Engine_State) return Boolean
   with Ghost;
   function Response_Header_Matches_Request
     (State : Engine_State; Packet : SMB.Bytes; Interim : Boolean)
      return Boolean
   with Ghost;
   function Pending_Request_Matches
     (State : Engine_State;
      Expected : Request_Expectation) return Boolean
   with Post =>
     (if Pending_Request_Matches'Result then
        Pending_Command (State) = Expected.Command
        and then Pending_Response_Is_Signed (State) = Expected.Signed);
   function Create_Receipt_Matches_File_Id
     (State : Engine_State;
      File_Id : SMB.Bytes) return Boolean
   with Ghost;
   function Close_Receipt_Matches
     (State : Engine_State;
      Token : Handle_Token) return Boolean
   with Ghost;
   procedure Initialize
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Global => (In_Out => Identity_Registry),
     Post =>
       (if Status = SMB.Ok then
          Current_Phase (State) = Disconnected
          and Current_Owner_Id (State) /= 0
          and not Has_Open_Handles (State)
          and not Has_Pending_Request (State)
          and Current_Async_Id (State) = 0
          and Signing_Key_Is_Zero (State));

   procedure Mark_Connected
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Current_Phase (State) = Transport_Connected);

   procedure Mark_Negotiated
     (State : in out Engine_State;
      Maximum_Read, Maximum_Write : Natural;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Current_Phase (State'Old) = Transport_Connected
          and not Has_Pending_Request (State'Old)
          and Response_Receipt_Matches
            (State'Old, 0, SMB.Success, False, False)
          and Current_Response_Info (State'Old).Max_Read = Maximum_Read
          and Current_Response_Info (State'Old).Max_Write = Maximum_Write
          and
          Current_Phase (State) = Negotiated
          and Current_Owner_Id (State) = Current_Owner_Id (State'Old)
          and Current_Epoch (State) = Current_Epoch (State'Old)
          and Current_Tree_Id (State) = Current_Tree_Id (State'Old)
          and Current_Signing_Key (State) = Current_Signing_Key (State'Old)
          and Has_Signing_Key (State) = Has_Signing_Key (State'Old)
          and Handle_Table_Equivalent (State'Old, State)
          and Current_Max_Read (State) = Maximum_Read
          and Current_Max_Write (State) = Maximum_Write
          and Current_Session_Id (State) = 0
          and not Has_Validated_Response (State)
          and not Has_Pending_Request (State)
        else State = State'Old);

   procedure Install_Session_Key
     (State : in out Engine_State;
      Session_Id : SMB.QWord;
      Key : SMB.Bytes;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Current_Owner_Id (State) = Current_Owner_Id (State'Old)
          and Current_Epoch (State) = Current_Epoch (State'Old)
          and Current_Phase (State'Old) = Negotiated
          and not Has_Pending_Request (State'Old)
          and Response_Receipt_Matches
            (State'Old, 1, SMB.Status_More_Processing_Required, False, False)
          and Current_Response_Info (State'Old).Session_Id = Session_Id
          and not Has_Signing_Key (State'Old)
          and not Has_Pending_Request (State'Old)
          and Session_Id /= 0
          and Key'Length = 16
          and
          Has_Signing_Key (State)
          and Current_Session_Id (State) = Session_Id
          and Current_Signing_Key (State) = Key
          and not Has_Validated_Response (State));

   procedure Mark_Authenticated
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Current_Owner_Id (State) = Current_Owner_Id (State'Old)
          and Current_Epoch (State) = Current_Epoch (State'Old)
          and Current_Phase (State'Old) = Negotiated
          and Has_Signing_Key (State'Old)
          and not Has_Pending_Request (State'Old)
          and Response_Receipt_Matches (State'Old, 1, SMB.Success, True, True)
          and Current_Response_Info (State'Old).Session_Id =
            Current_Session_Id (State'Old)
          and
          Current_Phase (State) = Authenticated
          and Current_Session_Id (State) = Current_Session_Id (State'Old)
          and Has_Signing_Key (State)
          and not Has_Validated_Response (State));

   procedure Mark_Share_Connected
     (State : in out Engine_State;
      Tree_Id : SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Status = SMB.Ok then
          Current_Phase (State'Old) = Authenticated
          and not Has_Pending_Request (State'Old)
          and Tree_Id /= 0
          and Response_Receipt_Matches (State'Old, 3, SMB.Success, True, False)
          and Current_Response_Info (State'Old).Tree_Id = Tree_Id
          and
          Current_Phase (State) = Share_Connected
          and Current_Owner_Id (State) = Current_Owner_Id (State'Old)
          and Current_Epoch (State) = Current_Epoch (State'Old)
          and Current_Session_Id (State) = Current_Session_Id (State'Old)
          and Current_Signing_Key (State) = Current_Signing_Key (State'Old)
          and Has_Signing_Key (State) = Has_Signing_Key (State'Old)
          and Handle_Table_Equivalent (State'Old, State)
          and Current_Tree_Id (State) = Tree_Id
          and not Has_Validated_Response (State)
          and not Has_Pending_Request (State)
        else State = State'Old);

   procedure Begin_Request
     (State : in out Engine_State;
      Command : SMB.Core_Wire.Command_Code;
      Request_Signed : Boolean;
      Response_Signed : Boolean;
      Message_Id : out SMB.QWord;
      Expected : out Request_Expectation;
      Status : out SMB.Core_Status;
      Request_Amount : Natural := 0;
      Close_Token : Handle_Token := (others => 0))
   with
     Post =>
       Connection_Context_Equivalent (State'Old, State)
       and then
       Current_Owner_Id (State) = Current_Owner_Id (State'Old)
       and then Current_Epoch (State) = Current_Epoch (State'Old)
       and then
         (if Status /= SMB.Ok and then not Has_Validated_Response (State'Old)
          then State = State'Old)
       and then
       (if Status = SMB.Ok then
          Has_Pending_Request (State)
          and not Has_Validated_Response (State)
          and Current_Async_Id (State) = 0
          and Expected.Command = Command
          and Message_Id = Expected.Message_Id
          and Expected.Request_Signed = Request_Signed
          and Expected.Signed = Response_Signed
          and Expected.Request_Amount = Request_Amount
          and Expected.Session_Id = Current_Session_Id (State)
          and Expected.Tree_Id =
            (if Command = 0 or else Command = 2 or else Command = 3
             then 0 else Current_Tree_Id (State))
          and Current_Session_Id (State) = Current_Session_Id (State'Old)
          and Current_Phase (State) = Current_Phase (State'Old)
          and Has_Signing_Key (State) = Has_Signing_Key (State'Old)
          and Handle_Table_Equivalent (State'Old, State)
          and Pending_Request_Matches (State, Expected)
        else Message_Id = 0);

   procedure Inspect_Interim_Response
     (State : in out Engine_State;
      Packet : SMB.Bytes;
      Is_Interim : out Boolean;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          (if Is_Interim then
             Interim_Context_Equivalent (State'Old, State)
             and then Has_Pending_Request (State'Old)
             and then Has_Pending_Request (State)
             and then not Has_Validated_Response (State)
             and then Current_Async_Id (State) /= 0
             and then Packet'Length >= 72
             and then Current_Async_Id (State) =
               SMB.Core_Wire.Encoded_U64 (Packet, 32)
             and then Response_Header_Matches_Request
               (State'Old, Packet, True)
             and then
               (if Current_Async_Id (State'Old) /= 0 then
                  Current_Async_Id (State) = Current_Async_Id (State'Old))
           else State = State'Old)
        else
          not Is_Interim
          and then Current_Phase (State) = Disconnected
          and then not Has_Signing_Key (State)
          and then Current_Session_Id (State) = 0
          and then Current_Tree_Id (State) = 0
          and then Current_Async_Id (State) = 0
          and then not Has_Pending_Request (State)
          and then not Has_Validated_Response (State)
          and then not Has_Open_Handles (State)
          and then Signing_Key_Is_Zero (State));

   procedure Accept_Response
     (State : in out Engine_State;
      Packet : SMB.Bytes;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status /= SMB.Ok then
          Current_Phase (State) = Disconnected
          and not Has_Signing_Key (State)
          and Current_Session_Id (State) = 0
          and Current_Tree_Id (State) = 0
          and Current_Async_Id (State) = 0
          and Nt_Status = 0
          and not Has_Pending_Request (State)
          and not Has_Validated_Response (State)
          and not Has_Open_Handles (State)
          and Signing_Key_Is_Zero (State)
        else
          Packet'Length >= SMB.Core_Wire.Header_Size
          and then Response_Header_Matches_Request (State'Old, Packet, False)
          and then Nt_Status = SMB.Core_Wire.Header_Nt_Status (Packet)
          and then
          (if Pending_Command (State'Old) = 2
                and then Nt_Status = SMB.Success
           then True
           else Current_Owner_Id (State) = Current_Owner_Id (State'Old)
             and then Current_Epoch (State) = Current_Epoch (State'Old))
          and then
          not Has_Pending_Request (State)
          and then Current_Async_Id (State) = 0
          and then
            (if Pending_Command (State'Old) = 4
               and then Nt_Status = SMB.Success
             then Current_Phase (State) = Authenticated
               and Current_Tree_Id (State) = 0
               and Current_Session_Id (State) = Current_Session_Id (State'Old)
               and Current_Signing_Key (State) = Current_Signing_Key (State'Old)
               and Has_Signing_Key (State) = Has_Signing_Key (State'Old)
               and not Has_Open_Handles (State)
               and not Has_Validated_Response (State)
             elsif Pending_Command (State'Old) = 2
               and then Nt_Status = SMB.Success
             then Current_Phase (State) = Disconnected
               and Signing_Key_Is_Zero (State)
               and not Has_Signing_Key (State)
               and Current_Session_Id (State) = 0
               and Current_Tree_Id (State) = 0
               and not Has_Open_Handles (State)
               and not Has_Validated_Response (State)
             else Connection_Context_Equivalent (State'Old, State)
               and then Response_Receipt_Matches
               (State, Pending_Command (State'Old), Nt_Status,
                Pending_Response_Is_Signed (State'Old),
                Pending_Command (State'Old) = 1
                  and then Nt_Status = SMB.Success)
               and then
                 (if Pending_Command (State'Old) = 0
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 128
                    and then Current_Response_Info (State).Max_Read in
                      1 .. SMB.Core_Protocol.Maximum_IO_Chunk
                    and then Current_Response_Info (State).Max_Write in
                      1 .. SMB.Core_Protocol.Maximum_IO_Chunk
                    and then Current_Response_Info (State).Max_Read =
                      Natural (SMB.DWord'Min
                        (SMB.Core_Protocol.Maximum_IO_Chunk,
                         SMB.Core_Wire.Encoded_U32 (Packet, 96)))
                    and then Current_Response_Info (State).Max_Write =
                      Natural (SMB.DWord'Min
                        (SMB.Core_Protocol.Maximum_IO_Chunk,
                         SMB.Core_Wire.Encoded_U32 (Packet, 100)))
                  elsif Pending_Command (State'Old) = 3
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 80
                    and then Current_Response_Info (State).Tree_Id /= 0
                    and then Current_Response_Info (State).Tree_Id =
                      SMB.Core_Wire.Encoded_U32 (Packet, 36))
               and then
                 (if Pending_Command (State'Old) = 1
                    and then Nt_Status =
                      SMB.Status_More_Processing_Required
                  then Packet'Length >= 72
                    and then Current_Response_Info (State).Data_Offset =
                      Natural (SMB.Core_Wire.Encoded_U16 (Packet, 68))
                    and then Current_Response_Info (State).Data_Length =
                      Natural (SMB.Core_Wire.Encoded_U16 (Packet, 70)))
               and then
                 (if Pending_Command (State'Old) = 8
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 80
                    and then Current_Response_Info (State).Data_Offset =
                      Natural (Packet (Packet'First + 66))
                    and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                      SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                    and then Current_Response_Info (State).Data_Length =
                      Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                  elsif Pending_Command (State'Old) = 9
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 80
                    and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                      SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                    and then Current_Response_Info (State).Count =
                      Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                  elsif Pending_Command (State'Old) = 14
                    and then Nt_Status = SMB.Success
                  then Packet'Length >= 72
                    and then SMB.Core_Wire.Encoded_U32 (Packet, 68) <=
                      SMB.DWord (SMB.Core_Protocol.Maximum_IO_Chunk)
                    and then Current_Response_Info (State).Data_Offset =
                      Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66))
                    and then Current_Response_Info (State).Data_Length <=
                      SMB.Core_Protocol.Maximum_IO_Chunk
                    and then Current_Response_Info (State).Data_Length =
                      Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68))
                    and then
                      (Current_Response_Info (State).Data_Length = 0
                       or else Current_Response_Info (State).Data_Offset >= 72)
                    and then Current_Response_Info (State).Data_Offset <=
                      Packet'Length
                    and then Current_Response_Info (State).Data_Length <=
                      Packet'Length -
                        Current_Response_Info (State).Data_Offset
                    ))
               and then
                 (if Pending_Command (State'Old) = 17 then
                    Current_Phase (State) = Current_Phase (State'Old)
                    and then Handle_Table_Equivalent (State'Old, State)));
   --  A failed wire/signature check invalidates the session and all handles.

   procedure Register_Handle
     (State : in out Engine_State;
      File_Id : SMB.Bytes;
      Access_Mode : Access_Kind;
      Is_Directory : Boolean;
      Token : out Handle_Token;
      Status : out SMB.Core_Status)
   with
      Post =>
       (if Status = SMB.Ok then
          Current_Phase (State'Old) = Share_Connected
          and not Has_Pending_Request (State'Old)
          and Create_Receipt_Matches_File_Id (State'Old, File_Id)
          and
          Handle_Matches (State, Token, File_Id, Access_Mode, Is_Directory)
          and Other_Handles_Preserved (State'Old, State)
          and not Has_Validated_Response (State)
        else State = State'Old
          and Token.Owner = 0 and Token.Epoch = 0 and Token.Ticket = 0);

   procedure Validate_Handle
     (State : Engine_State;
      Token : Handle_Token;
      Need_Read, Need_Write : Boolean;
      File_Id : out SMB.Bytes;
      Access_Mode : out Access_Kind;
      Is_Directory : out Boolean;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if File_Id'Length = 16 then
          (Status = SMB.Ok) =
            Valid_Handle (State, Token, Need_Read, Need_Write)
          and then
            (if Status = SMB.Ok then
               Handle_Matches (State, Token, File_Id, Access_Mode, Is_Directory)
             else Status = SMB.Invalid_Handle_Status)
        else Status = SMB.Invalid_Length)
       and then
         (if Status /= SMB.Ok then
            (for all Index in File_Id'Range => File_Id (Index) = 0)
            and then Access_Mode = Read_Only
            and then not Is_Directory);

   procedure Discard_Response_Receipt
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Connection_Context_Equivalent (State'Old, State)
       and then Current_Phase (State) = Current_Phase (State'Old)
       and then Current_Owner_Id (State) = Current_Owner_Id (State'Old)
       and then Current_Epoch (State) = Current_Epoch (State'Old)
       and then Current_Session_Id (State) =
         Current_Session_Id (State'Old)
       and then Current_Tree_Id (State) = Current_Tree_Id (State'Old)
       and then Current_Max_Read (State) = Current_Max_Read (State'Old)
       and then Current_Max_Write (State) = Current_Max_Write (State'Old)
       and then Has_Signing_Key (State) = Has_Signing_Key (State'Old)
       and then Current_Signing_Key (State) =
         Current_Signing_Key (State'Old)
       and then Handle_Table_Equivalent (State'Old, State)
       and then (if Status = SMB.Ok then
          not Has_Validated_Response (State)
          and not Has_Pending_Request (State));

   procedure Close_Handle
     (State : in out Engine_State;
      Token : Handle_Token;
      Status : out SMB.Core_Status;
      Close_Token : Handle_Token := (others => 0))
   with
     Post =>
       (if Status = SMB.Ok then
          Current_Phase (State'Old) = Share_Connected
          and not Has_Pending_Request (State'Old)
          and Valid_Handle (State'Old, Token, False, False)
          and Close_Receipt_Matches (State'Old, Token)
          and Close_Token.Owner = Token.Owner
          and Close_Token.Epoch = Token.Epoch
          and Close_Token.Ticket = Token.Ticket
          and
          not Valid_Handle (State, Token, False, False)
          and Other_Handles_Preserved (State'Old, State, Token.Ticket)
          and not Has_Validated_Response (State)
        else State = State'Old and Status = SMB.Invalid_Handle_Status);

   procedure Invalidate
     (State : in out Engine_State;
      Status : out SMB.Core_Status)
   with
     Post =>
       Current_Phase (State) = Disconnected
       and not Has_Open_Handles (State)
       and not Has_Pending_Request (State)
       and not Has_Validated_Response (State)
       and Signing_Key_Is_Zero (State)
       and not Has_Signing_Key (State)
       and Current_Session_Id (State) = 0
       and Current_Tree_Id (State) = 0
       and Current_Async_Id (State) = 0
       and Status =
         (if Current_Epoch (State)'Old = SMB.QWord'Last
          then SMB.Counter_Exhausted
          else SMB.Ok)
       and
         (Current_Epoch (State) > Current_Epoch (State)'Old
          or Current_Owner_Id (State) = 0);

   function Current_Signing_Key (State : Engine_State) return SMB.Bytes
   with Post => Current_Signing_Key'Result'Length = 16;

private
   use type SMB.Word;

   type Handle_Record is record
      Active : Boolean := False;
      Ticket : SMB.QWord := 0;
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Access_Mode : Access_Kind := Read_Only;
      Is_Directory : Boolean := False;
   end record;

   subtype Handle_Slot is Natural range 0 .. Maximum_Handles - 1;
   type Handle_Table is array (Handle_Slot)
      of Handle_Record;

   type Engine_State is record
      Current : Phase := Disconnected;
      Owner_Id : SMB.QWord := 0;
      Epoch : SMB.QWord := 0;
      Next_Message_Id : SMB.QWord := 0;
      Next_Ticket : SMB.QWord := 0;
      Session_Id : SMB.QWord := 0;
      Tree_Id : SMB.DWord := 0;
      Max_Read : Natural := 0;
      Max_Write : Natural := 0;
      Signing_Key : SMB.Bytes (0 .. 15) := (others => 0);
      Has_Key : Boolean := False;
      Pending : Boolean := False;
      Pending_Async_Id : SMB.QWord := 0;
      Pending_Expected : Request_Expectation;
      Receipt_Valid : Boolean := False;
      Receipt_Command : SMB.Core_Wire.Command_Code := 0;
      Receipt_Status : SMB.DWord := 0;
      Receipt_Signed : Boolean := False;
      Receipt_MIC_Valid : Boolean := False;
      Receipt_Close_Token : Handle_Token := (others => 0);
      Receipt_Info : SMB.Core_Protocol.Response_Info;
      Handles : Handle_Table;
   end record;

   function Has_Pending_Request (State : Engine_State) return Boolean is
     (State.Pending);

   function Has_Validated_Response (State : Engine_State) return Boolean is
     (State.Receipt_Valid);

   function Pending_Request_Matches
     (State : Engine_State;
      Expected : Request_Expectation) return Boolean is
     (State.Pending
      and then State.Pending_Expected.Command = Expected.Command
      and then State.Pending_Expected.Message_Id = Expected.Message_Id
      and then State.Pending_Expected.Session_Id = Expected.Session_Id
      and then State.Pending_Expected.Tree_Id = Expected.Tree_Id
      and then State.Pending_Expected.Request_Signed =
        Expected.Request_Signed
      and then State.Pending_Expected.Signed = Expected.Signed
      and then State.Pending_Expected.Request_Amount =
        Expected.Request_Amount
      and then State.Pending_Expected.Close_Token.Owner =
        Expected.Close_Token.Owner
      and then State.Pending_Expected.Close_Token.Epoch =
        Expected.Close_Token.Epoch
      and then State.Pending_Expected.Close_Token.Ticket =
        Expected.Close_Token.Ticket);

   function Pending_Command
     (State : Engine_State) return SMB.Core_Wire.Command_Code is
     (State.Pending_Expected.Command);

   function Pending_Response_Is_Signed
     (State : Engine_State) return Boolean is
     (State.Pending_Expected.Signed);

   function Response_Header_Matches_Request
     (State : Engine_State; Packet : SMB.Bytes; Interim : Boolean)
      return Boolean is
     (State.Pending
      and then Packet'Length >= SMB.Core_Wire.Header_Size
      and then Packet'Length <= SMB.Maximum_Frame_Size
      and then SMB.Core_Wire.Encoded_U16 (Packet, 12) =
        SMB.Word (State.Pending_Expected.Command)
      and then SMB.Core_Wire.Encoded_U64 (Packet, 24) =
        State.Pending_Expected.Message_Id
      and then
        (if State.Pending_Expected.Match_Session then
           SMB.Core_Wire.Encoded_U64 (Packet, 40) =
             State.Pending_Expected.Session_Id)
      and then
        (if State.Pending_Expected.Match_Tree
           and not Interim and State.Pending_Async_Id = 0
         then
           SMB.Core_Wire.Encoded_U32 (Packet, 36) =
             State.Pending_Expected.Tree_Id)
      and then (SMB.Core_Wire.Encoded_U32 (Packet, 16) and 1) /= 0
      and then ((SMB.Core_Wire.Encoded_U32 (Packet, 16) and 2) /= 0) =
        (Interim or State.Pending_Async_Id /= 0)
      and then (SMB.Core_Wire.Header_Nt_Status (Packet) = SMB.Status_Pending) =
        Interim
      and then
        (if Interim or State.Pending_Async_Id /= 0 then
           SMB.Core_Wire.Encoded_U64 (Packet, 32) /= 0
           and then
             (if State.Pending_Async_Id /= 0 then
                SMB.Core_Wire.Encoded_U64 (Packet, 32) = State.Pending_Async_Id))
      and then
        (if not Interim then
           ((SMB.Core_Wire.Encoded_U32 (Packet, 16) and 8) /= 0) =
             State.Pending_Expected.Signed));

end SMB.Engine;
