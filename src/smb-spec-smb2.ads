with SMB.Spec.Encoding;

--  The SMB2 packet header (MS-SMB2 2.2.1), as the specification that the
--  core's header writers and readers are proved against. Its fields are
--  little-endian (SMB.Spec.Encoding) at the offsets of 2.2.1.2; a header is
--  a record of the field values, and Is_Sync_Header says when bytes encode
--  one.
package SMB.Spec.SMB2
  with Ghost, SPARK_Mode
is
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;

   --  2.2.1: StructureSize "MUST be set to 64".
   Header_Size : constant := 64;

   --  2.2.1: ProtocolId, 0xFE then 'S', 'M', 'B'.
   function Protocol_Id_Byte (Index : Natural) return SMB.Byte is
     (case Index is
         when 0 => 16#FE#,
         when 1 => 16#53#,
         when 2 => 16#4D#,
         when others => 16#42#)
   with Pre => Index < 4;

   --  2.2.1.2: the Command field.
   Negotiate : constant SMB.Word := 16#0000#;
   Session_Setup : constant SMB.Word := 16#0001#;
   Logoff : constant SMB.Word := 16#0002#;
   Tree_Connect : constant SMB.Word := 16#0003#;
   Tree_Disconnect : constant SMB.Word := 16#0004#;
   Create : constant SMB.Word := 16#0005#;
   Close : constant SMB.Word := 16#0006#;
   Flush : constant SMB.Word := 16#0007#;
   Read : constant SMB.Word := 16#0008#;
   Write : constant SMB.Word := 16#0009#;
   Lock : constant SMB.Word := 16#000A#;
   Ioctl : constant SMB.Word := 16#000B#;
   Cancel : constant SMB.Word := 16#000C#;
   Echo : constant SMB.Word := 16#000D#;
   Query_Directory : constant SMB.Word := 16#000E#;
   Change_Notify : constant SMB.Word := 16#000F#;
   Query_Info : constant SMB.Word := 16#0010#;
   Set_Info : constant SMB.Word := 16#0011#;
   Oplock_Break : constant SMB.Word := 16#0012#;

   --  2.2.1.2: the Flags field.
   Flags_Server_To_Redir : constant SMB.DWord := 16#0000_0001#;
   Flags_Async_Command : constant SMB.DWord := 16#0000_0002#;
   Flags_Related_Operations : constant SMB.DWord := 16#0000_0004#;
   Flags_Signed : constant SMB.DWord := 16#0000_0008#;
   Flags_Priority_Mask : constant SMB.DWord := 16#0000_0070#;
   Flags_DFS_Operations : constant SMB.DWord := 16#1000_0000#;
   Flags_Replay_Operation : constant SMB.DWord := 16#2000_0000#;

   subtype Signature_Field is SMB.Bytes (0 .. 15);

   --  2.2.1.2, the SYNC header, field by field. Status is the
   --  (ChannelSequence/Reserved)/Status field: in a request of the SMB 3.x
   --  dialects its first two bytes are the ChannelSequence; Credits is the
   --  CreditRequest of a request and the CreditResponse of a response.
   type Sync_Header is record
      Credit_Charge : SMB.Word;
      Status : SMB.DWord;
      Command : SMB.Word;
      Credits : SMB.Word;
      Flags : SMB.DWord;
      Next_Command : SMB.DWord;
      Message_Id : SMB.QWord;
      Reserved : SMB.DWord;
      Tree_Id : SMB.DWord;
      Session_Id : SMB.QWord;
      Signature : Signature_Field;
   end record;

   --  Data starts with the encoding of Header: ProtocolId, then each field
   --  little-endian at its offset in 2.2.1.2 (the AsyncId of an ASYNC
   --  header would take the Reserved and TreeId bytes). Since a
   --  little-endian read determines its bytes, this fixes all 64.
   function Is_Sync_Header
     (Data : SMB.Bytes; Header : Sync_Header) return Boolean is
     (Data'Length >= Header_Size
      and then
        (for all Index in 0 .. 3 =>
           Data (Data'First + Index) = Protocol_Id_Byte (Index))
      and then SMB.Spec.Encoding.LE16 (Data, 4) = Header_Size
      and then SMB.Spec.Encoding.LE16 (Data, 6) = Header.Credit_Charge
      and then SMB.Spec.Encoding.LE32 (Data, 8) = Header.Status
      and then SMB.Spec.Encoding.LE16 (Data, 12) = Header.Command
      and then SMB.Spec.Encoding.LE16 (Data, 14) = Header.Credits
      and then SMB.Spec.Encoding.LE32 (Data, 16) = Header.Flags
      and then SMB.Spec.Encoding.LE32 (Data, 20) = Header.Next_Command
      and then SMB.Spec.Encoding.LE64 (Data, 24) = Header.Message_Id
      and then SMB.Spec.Encoding.LE32 (Data, 32) = Header.Reserved
      and then SMB.Spec.Encoding.LE32 (Data, 36) = Header.Tree_Id
      and then SMB.Spec.Encoding.LE64 (Data, 40) = Header.Session_Id
      and then
        (for all Index in 0 .. 15 =>
           Data (Data'First + 48 + Index) = Header.Signature (Index)))
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   --  The header of a request from this client, which never compounds
   --  requests and negotiates neither multichannel nor persistent handles:
   --  (ChannelSequence/Reserved)/Status zero (2.2.1.2: the Status of a
   --  request is set to 0, and 3.2.4.1 sets ChannelSequence only with those
   --  capabilities), NextCommand zero (not part of a compound), Reserved
   --  zero (2.2.1.2: the client "SHOULD set this field to 0"), and the
   --  Signature zero, which signing (3.2.4.1.1) then fills in when Flags
   --  has SMB2_FLAGS_SIGNED. The flags a request must not carry
   --  (SERVER_TO_REDIR, ASYNC_COMMAND) are the caller's to leave out; the
   --  validity predicates come with response acceptance (phase 7).
   function Request_Header
     (Command : SMB.Word;
      Credit_Charge : SMB.Word;
      Credit_Request : SMB.Word;
      Flags : SMB.DWord;
      Message_Id : SMB.QWord;
      Tree_Id : SMB.DWord;
      Session_Id : SMB.QWord) return Sync_Header is
     ((Credit_Charge => Credit_Charge,
       Status => 0,
       Command => Command,
       Credits => Credit_Request,
       Flags => Flags,
       Next_Command => 0,
       Message_Id => Message_Id,
       Reserved => 0,
       Tree_Id => Tree_Id,
       Session_Id => Session_Id,
       Signature => (others => 0)));

   --  2.2.14.1: SMB2_FILEID, Persistent then Volatile, 8 bytes each.
   subtype File_Id_Field is SMB.Bytes (0 .. 15);

   --  The bytes of Data from Offset on are Value.
   function Has_Bytes
     (Data : SMB.Bytes; Offset : Natural; Value : SMB.Bytes) return Boolean is
     (Offset <= Data'Length
      and then Value'Length <= Data'Length - Offset
      and then
        (for all Index in 0 .. Value'Length - 1 =>
           Data (Data'First + Offset + Index) = Value (Value'First + Index)))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Value'Length <= SMB.Maximum_Frame_Size;

   --  2.2.15: the SMB2 CLOSE Request, after the header.
   Close_Request_Size : constant := 24;
   Close_Flag_Postquery_Attrib : constant SMB.Word := 16#0001#;

   type Close_Request is record
      Flags : SMB.Word;
      File_Id : File_Id_Field;
   end record;

   --  StructureSize 24; Reserved "The client MUST set this to 0".
   function Is_Close_Request
     (Data : SMB.Bytes; Request : Close_Request) return Boolean is
     (Data'Length >= Close_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 0) = Close_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 2) = Request.Flags
      and then SMB.Spec.Encoding.LE32 (Data, 4) = 0
      and then Has_Bytes (Data, 8, Request.File_Id))
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  2.2.19: the SMB2 READ Request, after the header. StructureSize is 49
   --  "regardless of how long Buffer[] actually is", and counts one byte of
   --  Buffer, which carries the read channel information.
   Read_Request_Size : constant := 49;
   Channel_None : constant SMB.DWord := 16#0000_0000#;

   type Read_Request is record
      Padding : SMB.Byte;
      Flags : SMB.Byte;
      Length : SMB.DWord;
      Offset : SMB.QWord;
      File_Id : File_Id_Field;
      Minimum_Count : SMB.DWord;
      Channel : SMB.DWord;
      Remaining_Bytes : SMB.DWord;
      Read_Channel_Info_Offset : SMB.Word;
      Read_Channel_Info_Length : SMB.Word;
      Buffer : SMB.Byte;
   end record;

   function Is_Read_Request
     (Data : SMB.Bytes; Request : Read_Request) return Boolean is
     (Data'Length >= Read_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 0) = Read_Request_Size
      and then Data (Data'First + 2) = Request.Padding
      and then Data (Data'First + 3) = Request.Flags
      and then SMB.Spec.Encoding.LE32 (Data, 4) = Request.Length
      and then SMB.Spec.Encoding.LE64 (Data, 8) = Request.Offset
      and then Has_Bytes (Data, 16, Request.File_Id)
      and then SMB.Spec.Encoding.LE32 (Data, 32) = Request.Minimum_Count
      and then SMB.Spec.Encoding.LE32 (Data, 36) = Request.Channel
      and then SMB.Spec.Encoding.LE32 (Data, 40) = Request.Remaining_Bytes
      and then
        SMB.Spec.Encoding.LE16 (Data, 44) = Request.Read_Channel_Info_Offset
      and then
        SMB.Spec.Encoding.LE16 (Data, 46) = Request.Read_Channel_Info_Length
      and then Data (Data'First + 48) = Request.Buffer)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The READ this client sends (3.2.4.6), not over RDMA, asking for
   --  neither unbuffered nor compressed reads: Flags 0; "The Padding field
   --  SHOULD be set to 0x50"; MinimumCount "SHOULD" be 0 when the
   --  application gives none; in 3.1.1, Channel SMB2_CHANNEL_NONE and the
   --  channel information zero (MUST), RemainingBytes then "MUST be set to
   --  0" (2.2.19); "The first byte of the Buffer field MUST be set to 0".
   --  In 2.1, Channel is reserved and MUST be 0; the other channel fields
   --  are unused there, and this client sends them as zero too.
   function Client_Read
     (File_Id : File_Id_Field;
      Offset : SMB.QWord;
      Length : SMB.DWord) return Read_Request is
     ((Padding => 16#50#,
       Flags => 0,
       Length => Length,
       Offset => Offset,
       File_Id => File_Id,
       Minimum_Count => 0,
       Channel => Channel_None,
       Remaining_Bytes => 0,
       Read_Channel_Info_Offset => 0,
       Read_Channel_Info_Length => 0,
       Buffer => 0));

   --  2.2.21: the SMB2 WRITE Request, after the header: 48 bytes of fields
   --  (StructureSize 49 counts the first byte of Buffer too), then Buffer,
   --  which holds the data at DataOffset, counted from the start of the
   --  header.
   Write_Request_Size : constant := 49;
   Write_Fields_Size : constant := 48;

   type Write_Request is record
      Data_Offset : SMB.Word;
      Length : SMB.DWord;
      Offset : SMB.QWord;
      File_Id : File_Id_Field;
      Channel : SMB.DWord;
      Remaining_Bytes : SMB.DWord;
      Write_Channel_Info_Offset : SMB.Word;
      Write_Channel_Info_Length : SMB.Word;
      Flags : SMB.DWord;
   end record;

   --  The 48 bytes of fields.
   function Is_Write_Fields
     (Data : SMB.Bytes; Request : Write_Request) return Boolean is
     (Data'Length >= Write_Fields_Size
      and then SMB.Spec.Encoding.LE16 (Data, 0) = Write_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 2) = Request.Data_Offset
      and then SMB.Spec.Encoding.LE32 (Data, 4) = Request.Length
      and then SMB.Spec.Encoding.LE64 (Data, 8) = Request.Offset
      and then Has_Bytes (Data, 16, Request.File_Id)
      and then SMB.Spec.Encoding.LE32 (Data, 32) = Request.Channel
      and then SMB.Spec.Encoding.LE32 (Data, 36) = Request.Remaining_Bytes
      and then
        SMB.Spec.Encoding.LE16 (Data, 40) = Request.Write_Channel_Info_Offset
      and then
        SMB.Spec.Encoding.LE16 (Data, 42) = Request.Write_Channel_Info_Length
      and then SMB.Spec.Encoding.LE32 (Data, 44) = Request.Flags)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The fields, then Payload (Length bytes) at DataOffset, after the
   --  fields; "The client MUST fill the bytes, if any, between the beginning
   --  of the Buffer field and the beginning of the data (at DataOffset)
   --  with zeros" (3.2.4.7).
   function Is_Write_Request
     (Data : SMB.Bytes; Request : Write_Request; Payload : SMB.Bytes)
      return Boolean is
     (Is_Write_Fields (Data, Request)
      and then Natural (Request.Data_Offset) >= Header_Size + Write_Fields_Size
      and then SMB.QWord (Request.Length) = SMB.QWord (Payload'Length)
      and then Natural (Request.Data_Offset) - Header_Size <= Data'Length
      and then
        (for all Index in Write_Fields_Size ..
                          Natural (Request.Data_Offset) - Header_Size - 1 =>
           Data (Data'First + Index) = 0)
      and then
        Has_Bytes
          (Data, Natural (Request.Data_Offset) - Header_Size, Payload))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Payload'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The WRITE this client sends (3.2.4.7), not over RDMA, asking for
   --  neither write-through nor unbuffered writes (Flags 0): DataOffset is
   --  "an implementation-specific value", here the data straight after the
   --  fields (64 + 48 = 112); RemainingBytes "MUST be set to 0"; in 3.1.1,
   --  Channel SMB2_CHANNEL_NONE and the channel information zero (MUST). In
   --  2.1, Channel is reserved and MUST be 0, and the channel information
   --  fields, unused there, are zero too.
   function Client_Write
     (File_Id : File_Id_Field;
      Offset : SMB.QWord;
      Length : SMB.DWord) return Write_Request is
     ((Data_Offset => Header_Size + Write_Fields_Size,
       Length => Length,
       Offset => Offset,
       File_Id => File_Id,
       Channel => Channel_None,
       Remaining_Bytes => 0,
       Write_Channel_Info_Offset => 0,
       Write_Channel_Info_Length => 0,
       Flags => 0));

   --  A variable part that a request places by an offset counted from the
   --  start of the header (SecurityBufferOffset, PathOffset): Value at
   --  Offset, after the Fixed bytes of fields, in Data, which starts after
   --  the header.
   function Has_Bytes_At_Offset
     (Data : SMB.Bytes; Fixed : Natural; Offset : SMB.Word; Value : SMB.Bytes)
      return Boolean is
     (Natural (Offset) >= Header_Size
      and then Natural (Offset) - Header_Size >= Fixed
      and then Has_Bytes (Data, Natural (Offset) - Header_Size, Value))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Value'Length <= SMB.Maximum_Frame_Size;

   --  2.2.5: the SMB2 SESSION_SETUP Request, after the header: 24 bytes of
   --  fields (StructureSize 25 counts a byte of Buffer), then the security
   --  token at SecurityBufferOffset.
   Session_Setup_Request_Size : constant := 25;
   Session_Setup_Fields_Size : constant := 24;
   Negotiate_Signing_Enabled : constant SMB.Byte := 16#01#;
   Negotiate_Signing_Required : constant SMB.Byte := 16#02#;

   type Session_Setup_Request is record
      Flags : SMB.Byte;
      Security_Mode : SMB.Byte;
      Capabilities : SMB.DWord;
      Channel : SMB.DWord;
      Security_Buffer_Offset : SMB.Word;
      Security_Buffer_Length : SMB.Word;
      Previous_Session_Id : SMB.QWord;
   end record;

   function Is_Session_Setup_Request
     (Data : SMB.Bytes; Request : Session_Setup_Request; Token : SMB.Bytes)
      return Boolean is
     (Data'Length >= Session_Setup_Fields_Size
      and then
        SMB.Spec.Encoding.LE16 (Data, 0) = Session_Setup_Request_Size
      and then Data (Data'First + 2) = Request.Flags
      and then Data (Data'First + 3) = Request.Security_Mode
      and then SMB.Spec.Encoding.LE32 (Data, 4) = Request.Capabilities
      and then SMB.Spec.Encoding.LE32 (Data, 8) = Request.Channel
      and then
        SMB.Spec.Encoding.LE16 (Data, 12) = Request.Security_Buffer_Offset
      and then
        SMB.Spec.Encoding.LE16 (Data, 14) = Request.Security_Buffer_Length
      and then
        SMB.Spec.Encoding.LE64 (Data, 16) = Request.Previous_Session_Id
      and then Natural (Request.Security_Buffer_Length) = Token'Length
      and then
        Has_Bytes_At_Offset
          (Data, Session_Setup_Fields_Size, Request.Security_Buffer_Offset,
           Token))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Token'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The SESSION_SETUP this client sends (3.2.4.2.3), on its first
   --  channel and with no session to reconnect: "The Flags field MUST be
   --  set to 0"; it requires signing, so SMB2_NEGOTIATE_SIGNING_REQUIRED
   --  (MUST), with SMB2_NEGOTIATE_SIGNING_ENABLED too (2.2.5: the server
   --  ignores it); no DFS, so Capabilities 0; Channel 0 (2.2.5: "The client
   --  MUST set this to 0"); PreviousSessionId 0 (MUST); and the token right
   --  after the fields (64 + 24 = 88: the client's choice, since the offset
   --  only has to describe where the token is).
   function Client_Session_Setup
     (Token_Length : SMB.Word) return Session_Setup_Request is
     ((Flags => 0,
       Security_Mode =>
         Negotiate_Signing_Enabled + Negotiate_Signing_Required,
       Capabilities => 0,
       Channel => 0,
       Security_Buffer_Offset => Header_Size + Session_Setup_Fields_Size,
       Security_Buffer_Length => Token_Length,
       Previous_Session_Id => 0));

   --  2.2.9: the SMB2 TREE_CONNECT Request, after the header: 8 bytes of
   --  fields (StructureSize 9 counts a byte of Buffer), then the path,
   --  "\\server\share" in UTF-16, at PathOffset.
   Tree_Connect_Request_Size : constant := 9;
   Tree_Connect_Fields_Size : constant := 8;

   type Tree_Connect_Request is record
      Flags : SMB.Word;
      Path_Offset : SMB.Word;
      Path_Length : SMB.Word;
   end record;

   function Is_Tree_Connect_Request
     (Data : SMB.Bytes; Request : Tree_Connect_Request; Path : SMB.Bytes)
      return Boolean is
     (Data'Length >= Tree_Connect_Fields_Size
      and then SMB.Spec.Encoding.LE16 (Data, 0) = Tree_Connect_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 2) = Request.Flags
      and then SMB.Spec.Encoding.LE16 (Data, 4) = Request.Path_Offset
      and then SMB.Spec.Encoding.LE16 (Data, 6) = Request.Path_Length
      and then Natural (Request.Path_Length) = Path'Length
      and then
        Has_Bytes_At_Offset
          (Data, Tree_Connect_Fields_Size, Request.Path_Offset, Path))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Path'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The TREE_CONNECT this client sends (3.2.4.2.4), with no remoted
   --  identity, cluster reconnect or redirection: Flags 0 (in 2.1 the
   --  field is reserved and "The client MUST set this to 0"), and the path
   --  right after the fields (64 + 8 = 72, the client's choice). The form
   --  of the path (2.2.9's limits on the server and share components) is
   --  not part of this specification; the client checks only part of it.
   function Client_Tree_Connect
     (Path_Length : SMB.Word) return Tree_Connect_Request is
     ((Flags => 0,
       Path_Offset => Header_Size + Tree_Connect_Fields_Size,
       Path_Length => Path_Length));

   --  2.2.7 and 2.2.11: the SMB2 LOGOFF and TREE_DISCONNECT Requests, the
   --  same 4 bytes: StructureSize 4 and a Reserved field that "The client
   --  MUST set ... to 0".
   Logoff_Request_Size : constant := 4;
   Tree_Disconnect_Request_Size : constant := 4;

   function Is_Logoff_Request (Data : SMB.Bytes) return Boolean is
     (Data'Length >= Logoff_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 0) = Logoff_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 2) = 0)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   function Is_Tree_Disconnect_Request (Data : SMB.Bytes) return Boolean is
     (Data'Length >= Tree_Disconnect_Request_Size
      and then
        SMB.Spec.Encoding.LE16 (Data, 0) = Tree_Disconnect_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 2) = 0)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  2.2.13: the SMB2 CREATE Request, after the header: 56 bytes of
   --  fields (StructureSize 57 counts a byte of Buffer), then Buffer, "at
   --  least one byte in length", with the name at NameOffset.
   Create_Request_Size : constant := 57;
   Create_Fields_Size : constant := 56;
   Oplock_Level_None : constant SMB.Byte := 16#00#;
   Impersonation : constant SMB.DWord := 16#0000_0002#;
   File_Attribute_Directory : constant SMB.DWord := 16#0000_0010#;
   File_Share_Read_Write_Delete : constant SMB.DWord := 16#0000_0007#;
   File_Open : constant SMB.DWord := 1;
   File_Create : constant SMB.DWord := 2;
   File_Open_If : constant SMB.DWord := 3;
   File_Directory_File : constant SMB.DWord := 16#0000_0001#;
   File_Non_Directory_File : constant SMB.DWord := 16#0000_0040#;

   type Create_Request is record
      Security_Flags : SMB.Byte;
      Requested_Oplock_Level : SMB.Byte;
      Impersonation_Level : SMB.DWord;
      Smb_Create_Flags : SMB.QWord;
      Reserved : SMB.QWord;
      Desired_Access : SMB.DWord;
      File_Attributes : SMB.DWord;
      Share_Access : SMB.DWord;
      Create_Disposition : SMB.DWord;
      Create_Options : SMB.DWord;
      Name_Offset : SMB.Word;
      Name_Length : SMB.Word;
      Create_Contexts_Offset : SMB.DWord;
      Create_Contexts_Length : SMB.DWord;
   end record;

   --  The 56 bytes of fields.
   function Is_Create_Fields
     (Data : SMB.Bytes; Request : Create_Request) return Boolean is
     (Data'Length >= Create_Fields_Size
      and then SMB.Spec.Encoding.LE16 (Data, 0) = Create_Request_Size
      and then Data (Data'First + 2) = Request.Security_Flags
      and then Data (Data'First + 3) = Request.Requested_Oplock_Level
      and then SMB.Spec.Encoding.LE32 (Data, 4) = Request.Impersonation_Level
      and then SMB.Spec.Encoding.LE64 (Data, 8) = Request.Smb_Create_Flags
      and then SMB.Spec.Encoding.LE64 (Data, 16) = Request.Reserved
      and then SMB.Spec.Encoding.LE32 (Data, 24) = Request.Desired_Access
      and then SMB.Spec.Encoding.LE32 (Data, 28) = Request.File_Attributes
      and then SMB.Spec.Encoding.LE32 (Data, 32) = Request.Share_Access
      and then SMB.Spec.Encoding.LE32 (Data, 36) = Request.Create_Disposition
      and then SMB.Spec.Encoding.LE32 (Data, 40) = Request.Create_Options
      and then SMB.Spec.Encoding.LE16 (Data, 44) = Request.Name_Offset
      and then SMB.Spec.Encoding.LE16 (Data, 46) = Request.Name_Length
      and then
        SMB.Spec.Encoding.LE32 (Data, 48) = Request.Create_Contexts_Offset
      and then
        SMB.Spec.Encoding.LE32 (Data, 52) = Request.Create_Contexts_Length)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The fields, a Buffer of at least one byte, and the name at
   --  NameOffset, "the 8-byte aligned file name".
   function Is_Create_Request
     (Data : SMB.Bytes; Request : Create_Request; Name : SMB.Bytes)
      return Boolean is
     (Is_Create_Fields (Data, Request)
      and then Data'Length >= Create_Request_Size
      and then Request.Name_Offset mod 8 = 0
      and then Natural (Request.Name_Length) = Name'Length
      and then
        Has_Bytes_At_Offset
          (Data, Create_Fields_Size, Request.Name_Offset, Name))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Name'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The CREATE this client sends (3.2.4.3), with no create contexts and
   --  no oplock or lease: SecurityFlags 0 (2.2.13: "The client MUST set
   --  this to 0"); RequestedOplockLevel SMB2_OPLOCK_LEVEL_NONE (the client
   --  requests no oplock; when the server supports leasing, 3.2.4.3 says
   --  it "SHOULD" ask for a lease, which this client does not support);
   --  ImpersonationLevel Impersonation (the application gives none);
   --  SmbCreateFlags 0 (SHOULD) and Reserved 0 ("any value"); the
   --  application's DesiredAccess and CreateDisposition (a directory is
   --  opened or created: FILE_DIRECTORY_FILE "MUST" go with FILE_CREATE,
   --  FILE_OPEN_IF or FILE_OPEN); FileAttributes FILE_ATTRIBUTE_DIRECTORY
   --  for a directory, else 0; ShareAccess read, write and delete;
   --  CreateOptions FILE_DIRECTORY_FILE or FILE_NON_DIRECTORY_FILE; the
   --  name at the start of Buffer (NameOffset 64 + 56 = 120, as 2.2.13
   --  says it "SHOULD" be); and CreateContextsOffset and
   --  CreateContextsLength 0 (MUST, with no create contexts). The
   --  disposition is one of the six of 2.2.13 (MUST), and for a directory
   --  one of FILE_OPEN, FILE_CREATE and FILE_OPEN_IF. The form of the name
   --  (MS-FSCC 2.1.5, which 3.2.4.3 says the path MUST conform to) and the
   --  bits of DesiredAccess (2.2.13.1) are not part of this specification.
   function Client_Create
     (Desired_Access : SMB.DWord;
      Disposition : SMB.DWord;
      Directory : Boolean;
      Name_Length : SMB.Word) return Create_Request is
     ((Security_Flags => 0,
       Requested_Oplock_Level => Oplock_Level_None,
       Impersonation_Level => Impersonation,
       Smb_Create_Flags => 0,
       Reserved => 0,
       Desired_Access => Desired_Access,
       File_Attributes =>
         (if Directory then File_Attribute_Directory else 0),
       Share_Access => File_Share_Read_Write_Delete,
       Create_Disposition => Disposition,
       Create_Options =>
         (if Directory then File_Directory_File else File_Non_Directory_File),
       Name_Offset => Header_Size + Create_Fields_Size,
       Name_Length => Name_Length,
       Create_Contexts_Offset => 0,
       Create_Contexts_Length => 0))
   with Pre =>
     Disposition <= 5
     and then (if Directory then Disposition in File_Open .. File_Open_If);

   --  2.2.33: the SMB2 QUERY_DIRECTORY Request, after the header: 32 bytes
   --  of fields (StructureSize 33 counts a byte of Buffer), then the search
   --  pattern at FileNameOffset.
   Query_Directory_Request_Size : constant := 33;
   Query_Directory_Fields_Size : constant := 32;
   File_Id_Both_Directory_Information : constant SMB.Byte := 16#25#;
   Restart_Scans : constant SMB.Byte := 16#01#;

   type Query_Directory_Request is record
      File_Information_Class : SMB.Byte;
      Flags : SMB.Byte;
      File_Index : SMB.DWord;
      File_Id : File_Id_Field;
      File_Name_Offset : SMB.Word;
      File_Name_Length : SMB.Word;
      Output_Buffer_Length : SMB.DWord;
   end record;

   function Is_Query_Directory_Request
     (Data : SMB.Bytes; Request : Query_Directory_Request;
      Pattern : SMB.Bytes) return Boolean is
     (Data'Length >= Query_Directory_Fields_Size
      and then
        SMB.Spec.Encoding.LE16 (Data, 0) = Query_Directory_Request_Size
      and then Data (Data'First + 2) = Request.File_Information_Class
      and then Data (Data'First + 3) = Request.Flags
      and then SMB.Spec.Encoding.LE32 (Data, 4) = Request.File_Index
      and then Has_Bytes (Data, 8, Request.File_Id)
      and then SMB.Spec.Encoding.LE16 (Data, 24) = Request.File_Name_Offset
      and then SMB.Spec.Encoding.LE16 (Data, 26) = Request.File_Name_Length
      and then
        SMB.Spec.Encoding.LE32 (Data, 28) = Request.Output_Buffer_Length
      and then Natural (Request.File_Name_Length) = Pattern'Length
      --  FileNameOffset and FileNameLength "MUST be 0 if no search pattern
      --  is provided".
      and then
        (if Pattern'Length = 0 then Request.File_Name_Offset = 0
         else
           Has_Bytes_At_Offset
             (Data, Query_Directory_Fields_Size, Request.File_Name_Offset,
              Pattern)))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Pattern'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  "*" in UTF-16: every entry of the directory.
   Every_Name : constant SMB.Bytes (0 .. 1) := (16#2A#, 16#00#);

   --  The QUERY_DIRECTORY this client sends (3.2.4.17), a page of the whole
   --  directory: FileIdBothDirectoryInformation, SMB2_RESTART_SCANS on the
   --  first page, FileIndex 0 (2.2.33: without SMB2_INDEX_SPECIFIED it
   --  "MUST be set to zero"), the pattern "*" right after the fields
   --  (64 + 32 = 96), and OutputBufferLength 65536 (one credit's worth;
   --  the CreditCharge "MUST" then be 1).
   function Client_Query_Directory
     (File_Id : File_Id_Field; Restart : Boolean)
      return Query_Directory_Request is
     ((File_Information_Class => File_Id_Both_Directory_Information,
       Flags => (if Restart then Restart_Scans else 0),
       File_Index => 0,
       File_Id => File_Id,
       File_Name_Offset => Header_Size + Query_Directory_Fields_Size,
       File_Name_Length => Every_Name'Length,
       Output_Buffer_Length => 65_536));
end SMB.Spec.SMB2;
