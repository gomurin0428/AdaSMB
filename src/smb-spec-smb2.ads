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
end SMB.Spec.SMB2;
