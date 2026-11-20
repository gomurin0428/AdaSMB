with SMB.Spec.Encoding;
with SMB.Spec.SMB2.Negotiation;

--  The SMB2 TRANSFORM_HEADER (MS-SMB2 2.2.41), which carries an encrypted
--  message, and the header this client sends (3.1.4.3). Data starts at the
--  transform header, which takes the SMB2 header's place on the wire. The
--  Signature and the encrypted message after the header are the cipher's,
--  and are stated with it (docs/platinum-design.md, phase 6).
package SMB.Spec.SMB2.Transform
  with Ghost, SPARK_Mode
is
   --  ProtocolId (4 bytes), Signature (16), Nonce (16), OriginalMessageSize
   --  (4), Reserved (2), Flags (2) and SessionId (8).
   Transform_Header_Size : constant := 52;

   --  ProtocolId: "The value MUST be set to 0x424D53FD, also represented as
   --  (in network order) 0xFD, 'S', 'M', and 'B'".
   function Transform_Protocol_Id_Byte (Index : Natural) return SMB.Byte is
     (case Index is
         when 0 => 16#FD#,
         when 1 => 16#53#,
         when 2 => 16#4D#,
         when others => 16#42#)
   with Pre => Index < 4;

   --  Flags, in the SMB 3.1.1 dialect: "This field MUST be set to one of
   --  the following values", of which there is one, Encrypted.
   Flags_Encrypted : constant SMB.Word := 16#0001#;

   subtype Nonce_Field is SMB.Bytes (0 .. 15);

   --  The ciphers of SMB2_ENCRYPTION_CAPABILITIES (2.2.3.1.2).
   function Is_Cipher (Cipher : SMB.Word) return Boolean is
     (Cipher = SMB.Spec.SMB2.Negotiation.AES_128_CCM
      or else Cipher = SMB.Spec.SMB2.Negotiation.AES_128_GCM
      or else Cipher = SMB.Spec.SMB2.Negotiation.AES_256_CCM
      or else Cipher = SMB.Spec.SMB2.Negotiation.AES_256_GCM);

   --  Nonce, for the cipher: with AES-128-CCM or AES-256-CCM, AES_CCM_Nonce
   --  (11 bytes) and Reserved (5 bytes); with AES-128-GCM or AES-256-GCM,
   --  AES_GCM_Nonce (12 bytes) and Reserved (4 bytes).
   function Nonce_Size (Cipher : SMB.Word) return Natural is
     (if Cipher = SMB.Spec.SMB2.Negotiation.AES_128_CCM
         or else Cipher = SMB.Spec.SMB2.Negotiation.AES_256_CCM
      then 11
      else 12)
   with Pre => Is_Cipher (Cipher);

   type Transform_Header is record
      Nonce : Nonce_Field;
      Original_Message_Size : SMB.DWord;
      Reserved : SMB.Word;
      Flags : SMB.Word;
      Session_Id : SMB.QWord;
   end record;

   --  The fields of a TRANSFORM_HEADER but the Signature: ProtocolId, then
   --  Nonce at 20, OriginalMessageSize ("The size, in bytes, of the SMB2
   --  message") at 36, Reserved at 40, Flags at 42 and SessionId at 44.
   function Is_Transform_Header
     (Data : SMB.Bytes; Header : Transform_Header) return Boolean is
     (Data'Length >= Transform_Header_Size
      and then
        (for all Index in 0 .. 3 =>
           Data (Data'First + Index) = Transform_Protocol_Id_Byte (Index))
      and then Has_Bytes (Data, 20, Header.Nonce)
      and then
        SMB.Spec.Encoding.LE32 (Data, 36) = Header.Original_Message_Size
      and then SMB.Spec.Encoding.LE16 (Data, 40) = Header.Reserved
      and then SMB.Spec.Encoding.LE16 (Data, 42) = Header.Flags
      and then SMB.Spec.Encoding.LE64 (Data, 44) = Header.Session_Id)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The header a sender builds for Message_Size bytes of SMB2 message in
   --  the session (3.1.4.3, "Encrypting the Message"):
   --  * "OriginalMessageSize is set to the size of the SMB2 message being
   --    sent";
   --  * "SessionId is set to Session.SessionId";
   --  * "EncryptionAlgorithm/Flags is set to 0x0001";
   --  * Reserved: "The client MUST set this to zero";
   --  * Nonce: the cipher's Nonce_Size bytes of Nonce, a value "not used
   --    for any other encrypted message within the session" (keeping it so
   --    is the engine's part), then the Reserved bytes, which "The sender
   --    MUST set ... to 0" with GCM and "SHOULD" with CCM (footnote 83);
   --    this client sets them to 0 with either.
   function Client_Transform
     (Cipher : SMB.Word;
      Nonce : Nonce_Field;
      Message_Size : SMB.DWord;
      Session_Id : SMB.QWord) return Transform_Header is
     ((Nonce =>
         (for Index in Nonce_Field'Range =>
            (if Index < Nonce_Size (Cipher) then Nonce (Index) else 0)),
       Original_Message_Size => Message_Size,
       Reserved => 0,
       Flags => Flags_Encrypted,
       Session_Id => Session_Id))
   with Pre => Is_Cipher (Cipher);
end SMB.Spec.SMB2.Transform;
