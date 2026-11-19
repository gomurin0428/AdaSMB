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
end SMB.Spec.SMB2;
