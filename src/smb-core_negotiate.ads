--  SMB 3.1.1 negotiation (MS-SMB2 2.2.3, 2.2.4 and 3.2.5.2; the profile is in
--  docs/smb3-design.md): the NEGOTIATE request body with its two negotiate
--  contexts, and the checks on the negotiate contexts of a response that
--  selected 3.1.1. Packet offsets count from the start of the SMB2 header, as
--  the protocol's offset fields do.
package SMB.Core_Negotiate is
   pragma SPARK_Mode (On);

   use type SMB.Byte;
   use type SMB.Word;

   subtype Guid_Bytes is SMB.Bytes (0 .. 15);
   subtype Salt_Bytes is SMB.Bytes (0 .. 31);

   --  The request body: 36 fixed bytes, one or two dialects and padding to
   --  40, the preauth integrity context (46 bytes) and 2 bytes of padding,
   --  then the encryption context (18 bytes).
   Request_Length : constant := 106;
   subtype Request_Bytes is SMB.Bytes (0 .. Request_Length - 1);

   --  The ciphers in the order of their IDs on the wire, 1 to 4.
   type Cipher_Id is
     (No_Cipher, AES_128_CCM, AES_128_GCM, AES_256_CCM, AES_256_GCM);

   --  The body of a NEGOTIATE request that offers 3.1.1, and 2.1 too when
   --  Allow_21 is set. SecurityMode is 3 (signing enabled and required) and
   --  Capabilities is SMB2_GLOBAL_CAP_ENCRYPTION. The preauth integrity
   --  context offers SHA-512 with Salt, and the encryption context offers
   --  AES-128-GCM, AES-128-CCM, AES-256-GCM and AES-256-CCM, in the order a
   --  Windows client offers them by default; the server chooses. Its
   --  completion in the private part gives callers' proofs every byte; the
   --  postcondition repeats the fixed fields byte by byte, which provers
   --  find far more easily.
   function Request
     (Guid : Guid_Bytes; Salt : Salt_Bytes; Allow_21 : Boolean)
      return Request_Bytes
   with Post =>
     --  StructureSize 36, DialectCount, SecurityMode 3, Reserved.
     Request'Result (0) = 36 and then Request'Result (1) = 0
     and then Request'Result (2) = (if Allow_21 then 2 else 1)
     and then Request'Result (3) = 0
     and then Request'Result (4) = 3 and then Request'Result (5) = 0
     and then Request'Result (6) = 0 and then Request'Result (7) = 0
     --  Capabilities: SMB2_GLOBAL_CAP_ENCRYPTION.
     and then Request'Result (8) = 16#40# and then Request'Result (9) = 0
     and then Request'Result (10) = 0 and then Request'Result (11) = 0
     and then (for all Index in Guid_Bytes'Range =>
                 Request'Result (12 + Index) = Guid (Index))
     --  NegotiateContextOffset 104, NegotiateContextCount 2, Reserved2.
     and then Request'Result (28) = 104 and then Request'Result (29) = 0
     and then Request'Result (30) = 0 and then Request'Result (31) = 0
     and then Request'Result (32) = 2 and then Request'Result (33) = 0
     and then Request'Result (34) = 0 and then Request'Result (35) = 0
     --  The first dialect: 3.1.1.
     and then Request'Result (36) = 16#11# and then Request'Result (37) = 3;

   --  Checks the negotiate contexts of a NEGOTIATE response Packet (header
   --  included) that selected 3.1.1, and returns the cipher it chose.
   --  The connection must fail unless Status is Ok, which requires:
   --  * a first context at an 8-byte-aligned offset after the fixed body,
   --    and every context, each 8-byte aligned, inside the packet;
   --  * exactly one preauth integrity context, with one hash algorithm,
   --    SHA-512, and a salt that fits its data;
   --  * at most one encryption context, with one cipher that is 0 (none) or
   --    one we offered;
   --  * no compression, transport, RDMA or signing context: a server sends
   --    one only in answer to the client's, and we offer none.
   --  Other context types are ignored. Without an encryption context, or
   --  with cipher 0, Cipher is No_Cipher.
   procedure Check_Response_Contexts
     (Packet : SMB.Bytes;
      Cipher : out Cipher_Id;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post => Status in SMB.Ok | SMB.Invalid_Length | SMB.Invalid_Offset
                     | SMB.Invalid_Protocol
       and then (if Status /= SMB.Ok then Cipher = No_Cipher);

private

   subtype Two_Bytes is SMB.Bytes (0 .. 1);

   function LE16 (Value : SMB.Word) return Two_Bytes is
     (SMB.Byte (Value mod 2**8), SMB.Byte (Value / 2**8));

   --  The request's four-byte fields all hold values below 2**16, so each is
   --  written as LE16 of the value and two zero bytes.
   Zero_High : constant Two_Bytes := (0, 0);

   --  Negotiate context types (MS-SMB2 2.2.3.1) and the IDs we offer.
   Preauth_Integrity : constant SMB.Word := 1;
   Encryption : constant SMB.Word := 2;
   SHA_512 : constant SMB.Word := 1;
   CCM_Id : constant SMB.Word := 1;
   GCM_Id : constant SMB.Word := 2;
   CCM_256_Id : constant SMB.Word := 3;
   GCM_256_Id : constant SMB.Word := 4;

   --  The request's first context sits at body offset 40, which is 104 from
   --  the start of the header.
   Request_Context_Offset : constant := 64 + 40;

   function Request
     (Guid : Guid_Bytes; Salt : Salt_Bytes; Allow_21 : Boolean)
      return Request_Bytes
   is
     (LE16 (36)
      & LE16 (if Allow_21 then 2 else 1)
      & LE16 (3)
      & LE16 (0)
      & LE16 (16#40#) & Zero_High
      & Guid
      & LE16 (Request_Context_Offset) & Zero_High
      & LE16 (2)
      & LE16 (0)
      & LE16 (SMB.SMB2_Dialect_0311)
      --  The second dialect, or padding to the first context.
      & LE16 (if Allow_21 then SMB.SMB2_Dialect_0210 else 0)
      --  PREAUTH_INTEGRITY_CAPABILITIES: one hash algorithm, the salt's
      --  length, SHA-512 and the salt, then padding to the next context.
      & LE16 (Preauth_Integrity)
      & LE16 (6 + Salt_Bytes'Length)
      & LE16 (0) & Zero_High
      & LE16 (1)
      & LE16 (Salt_Bytes'Length)
      & LE16 (SHA_512)
      & Salt
      & LE16 (0)
      --  ENCRYPTION_CAPABILITIES: four ciphers, AES-128 first, GCM before
      --  CCM.
      & LE16 (Encryption)
      & LE16 (10)
      & LE16 (0) & Zero_High
      & LE16 (4)
      & LE16 (GCM_Id)
      & LE16 (CCM_Id)
      & LE16 (GCM_256_Id)
      & LE16 (CCM_256_Id));

end SMB.Core_Negotiate;
