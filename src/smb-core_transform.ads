with Interfaces;
with SMB.AES;
with SMB.Core_Negotiate;
with SMB.Core_Wire;

--  The SMB 3.x TRANSFORM_HEADER that carries an encrypted message (MS-SMB2
--  2.2.41, 3.1.4.3, 3.2.4.1.8 and 3.2.5.1.1.1):
--
--      0  ProtocolId           FD 'S' 'M' 'B'
--      4  Signature            the AEAD tag
--     20  Nonce                11 bytes (CCM) or 12 (GCM), then zeros
--     36  OriginalMessageSize  the message's length
--     40  Reserved             0
--     42  Flags                1, encrypted
--     44  SessionId
--     52  the encrypted message
--
--  Bytes 20 to 51 are the associated data, and the message is the whole SMB2
--  message from its header on. The proof covers run-time safety and the
--  contracts below; Microsoft's worked examples cover the bytes.
package SMB.Core_Transform is
   pragma SPARK_Mode (On);

   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type SMB.Core_Negotiate.Cipher_Id;

   Header_Size : constant := 52;
   --  The longest message whose transform fits in a frame.
   Maximum_Message_Size : constant := SMB.Maximum_Frame_Size - Header_Size;
   --  The SMB2 header that a decrypted message must start with.
   SMB2_Header_Size : constant := 64;

   subtype AEAD_Cipher is SMB.Core_Negotiate.Cipher_Id
     range SMB.Core_Negotiate.AES_128_CCM .. SMB.Core_Negotiate.AES_128_GCM;

   --  The contents of the Nonce field.
   subtype Nonce_Field is SMB.Bytes (0 .. 15);

   --  How many bytes of the Nonce field the cipher uses.
   function Nonce_Length (Cipher : AEAD_Cipher) return Positive is
     (case Cipher is
        when SMB.Core_Negotiate.AES_128_CCM => 11,
        when SMB.Core_Negotiate.AES_128_GCM => 12);

   --  Counter in little-endian order, then zeros: unique for each counter
   --  value with either cipher.
   function Counter_Nonce (Counter : SMB.QWord) return Nonce_Field is
     (SMB.Core_Wire.U64_Byte (Counter, 0),
      SMB.Core_Wire.U64_Byte (Counter, 1),
      SMB.Core_Wire.U64_Byte (Counter, 2),
      SMB.Core_Wire.U64_Byte (Counter, 3),
      SMB.Core_Wire.U64_Byte (Counter, 4),
      SMB.Core_Wire.U64_Byte (Counter, 5),
      SMB.Core_Wire.U64_Byte (Counter, 6),
      SMB.Core_Wire.U64_Byte (Counter, 7),
      0, 0, 0, 0, 0, 0, 0, 0);

   --  Whether Packet starts with the transform header's ProtocolId.
   function Is_Transformed (Packet : SMB.Bytes) return Boolean is
     (Packet'Length >= 4
      and then Packet (Packet'First) = 16#FD#
      and then Packet (Packet'First + 1) = 16#53#
      and then Packet (Packet'First + 2) = 16#4D#
      and then Packet (Packet'First + 3) = 16#42#);

   --  Writes Message, encrypted with Cipher and Key, after its transform
   --  header into Output, and zeros after them. The Nonce field holds the
   --  bytes of Nonce the cipher uses, then zeros. Output too short for the
   --  result fails with Invalid_Length and is all zero. Message and Output
   --  must not overlap: Output is cleared before Message is read. SPARK
   --  callers cannot pass overlapping arrays; other callers must not.
   procedure Seal
     (Cipher : AEAD_Cipher;
      Key : SMB.AES.Key_128;
      Nonce : Nonce_Field;
      Session_Id : SMB.QWord;
      Message : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Message'Length in 1 .. Maximum_Message_Size
       and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status in SMB.Ok | SMB.Invalid_Length
       and then
         (if Output'Length < Header_Size + Message'Length
          then Status = SMB.Invalid_Length and then Used = 0
            and then (for all Value of Output => Value = 0)
          else Status = SMB.Ok
            and then Used = Header_Size + Message'Length
            and then Is_Transformed (Output)
            and then
              (for all Index in Nonce_Field'Range =>
                 Output (Output'First + 20 + Index) =
                   (if Index < Nonce_Length (Cipher) then Nonce (Index)
                    else 0))
            and then SMB.Core_Wire.Encoded_U32 (Output, 36) =
              SMB.DWord (Message'Length)
            and then SMB.Core_Wire.Encoded_U16 (Output, 40) = 0
            and then SMB.Core_Wire.Encoded_U16 (Output, 42) = 1
            and then SMB.Core_Wire.Encoded_U64 (Output, 44) = Session_Id
            and then
              (for all Index in Output'Range =>
                 (if Index - Output'First >= Used
                  then Output (Index) = 0)));

   --  Checks the transform header of Packet, a whole received message, and
   --  decrypts the message after it in place. Status is, from the first
   --  check that fails:
   --  * Invalid_Length: Packet is no longer than the header;
   --  * Invalid_Protocol: another ProtocolId, or Flags is not 1;
   --  * Invalid_Length: OriginalMessageSize is not the length after the
   --    header;
   --  * Correlation_Error: SessionId is not Session_Id;
   --  * Signature_Error: the tag does not verify;
   --  * Invalid_Length: the message is shorter than an SMB2 header;
   --  * Invalid_Protocol: the message is not an SMB2 message (FE 'SMB'),
   --    such as another transform;
   --  * Correlation_Error: the message's SessionId is not Session_Id.
   --  Reserved is not checked, but the tag covers it. On any failure every
   --  byte after the header is zero; on Ok they are the message.
   procedure Unwrap
     (Cipher : AEAD_Cipher;
      Key : SMB.AES.Key_128;
      Session_Id : SMB.QWord;
      Packet : in out SMB.Bytes;
      Status : out SMB.Core_Status)
   with
     Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Status in SMB.Ok | SMB.Invalid_Length | SMB.Invalid_Protocol
                | SMB.Correlation_Error | SMB.Signature_Error
       and then
         (if Status = SMB.Ok then
            Packet'Length - Header_Size >= SMB2_Header_Size
            and then Is_Transformed (Packet)
            and then SMB.Core_Wire.Encoded_U32 (Packet, 36) =
              SMB.DWord (Packet'Length - Header_Size)
            and then SMB.Core_Wire.Encoded_U16 (Packet, 42) = 1
            and then SMB.Core_Wire.Encoded_U64 (Packet, 44) = Session_Id
            and then Packet (Packet'First + Header_Size) = 16#FE#
            and then Packet (Packet'First + Header_Size + 1) = 16#53#
            and then Packet (Packet'First + Header_Size + 2) = 16#4D#
            and then Packet (Packet'First + Header_Size + 3) = 16#42#
            and then SMB.Core_Wire.Encoded_U64
              (Packet, Header_Size + 40) = Session_Id
          else
            (for all Index in Packet'Range =>
               (if Index - Packet'First >= Header_Size
                then Packet (Index) = 0)));

end SMB.Core_Transform;
