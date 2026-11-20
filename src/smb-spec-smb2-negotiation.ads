with SMB.Spec.Encoding;

--  The SMB2 NEGOTIATE request (MS-SMB2 2.2.3) with SMB 3.1.1's negotiate
--  contexts (2.2.3.1), and this client's request (3.2.4.2.2.2). As in
--  SMB.Spec.SMB2, Data is the request after the header, its fields read at
--  their offsets, and the offset fields count from the start of the header.
package SMB.Spec.SMB2.Negotiation
  with Ghost, SPARK_Mode
is
   --  Bounded as SMB.Bytes's lengths are, so that a list's length is an
   --  Integer.
   subtype List_Index is Natural range 0 .. SMB.Maximum_Frame_Size;
   type Word_List is array (List_Index range <>) of SMB.Word;

   --  The elements of Words, each a little-endian 16-bit integer, from
   --  Offset of Data on: how the request lists dialects, and the contexts
   --  hash algorithms, ciphers and signing algorithms.
   function Has_Words
     (Data : SMB.Bytes; Offset : Natural; Words : Word_List) return Boolean is
     (Offset <= Data'Length
      and then Words'Length <= SMB.Maximum_Frame_Size / 2
      and then 2 * Words'Length <= Data'Length - Offset
      and then
        (for all Index in 0 .. Words'Length - 1 =>
           SMB.Spec.Encoding.LE16 (Data, Offset + 2 * Index) =
             Words (Words'First + Index)))
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   --  Every byte of Data from From up to To (excluded) is zero.
   function Is_Zero (Data : SMB.Bytes; From, To : Natural) return Boolean is
     (From <= To and then To <= Data'Length
      and then
        (for all Index in From .. To - 1 => Data (Data'First + Index) = 0))
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   --  The first multiple of 8 from Offset on.
   function Align_8 (Offset : Natural) return Natural is
     ((Offset + 7) / 8 * 8)
   with Pre => Offset <= SMB.Maximum_Frame_Size,
     Post =>
       Align_8'Result >= Offset
       and then Align_8'Result <= Offset + 7
       and then Align_8'Result mod 8 = 0;

   --  2.2.3: the fixed fields, which StructureSize counts: "The client MUST
   --  set this field to 36 ... regardless of the number of dialects or
   --  number of negotiate contexts sent". The Dialects array follows.
   Negotiate_Request_Size : constant := 36;

   Dialect_0202 : constant SMB.Word := 16#0202#;
   Dialect_0210 : constant SMB.Word := 16#0210#;
   Dialect_0300 : constant SMB.Word := 16#0300#;
   Dialect_0302 : constant SMB.Word := 16#0302#;
   Dialect_0311 : constant SMB.Word := 16#0311#;

   --  SecurityMode.
   Signing_Enabled : constant SMB.Word := 16#0001#;
   Signing_Required : constant SMB.Word := 16#0002#;

   --  Capabilities.
   Global_Cap_DFS : constant SMB.DWord := 16#0000_0001#;
   Global_Cap_Leasing : constant SMB.DWord := 16#0000_0002#;
   Global_Cap_Large_MTU : constant SMB.DWord := 16#0000_0004#;
   Global_Cap_Multi_Channel : constant SMB.DWord := 16#0000_0008#;
   Global_Cap_Persistent_Handles : constant SMB.DWord := 16#0000_0010#;
   Global_Cap_Directory_Leasing : constant SMB.DWord := 16#0000_0020#;
   Global_Cap_Encryption : constant SMB.DWord := 16#0000_0040#;
   Global_Cap_Notifications : constant SMB.DWord := 16#0000_0080#;

   type Negotiate_Request is record
      Dialect_Count : SMB.Word;
      Security_Mode : SMB.Word;
      Capabilities : SMB.DWord;
      Negotiate_Context_Offset : SMB.DWord;
      Negotiate_Context_Count : SMB.Word;
   end record;

   function Offers_0311 (Dialects : Word_List) return Boolean is
     (for some Dialect of Dialects => Dialect = Dialect_0311);

   --  The dialects 2.2.3 defines; Dialects "MUST contain at least one" of
   --  them.
   function Is_Known_Dialect (Dialect : SMB.Word) return Boolean is
     (Dialect = Dialect_0202 or else Dialect = Dialect_0210
      or else Dialect = Dialect_0300 or else Dialect = Dialect_0302
      or else Dialect = Dialect_0311);

   --  The fixed fields and the dialects of a NEGOTIATE request:
   --  * StructureSize 36;
   --  * DialectCount, the number of Dialects, which "MUST be greater than
   --    0";
   --  * Reserved: "The client MUST set this to 0";
   --  * ClientGuid, 16 bytes;
   --  * if Dialects contains 0x0311, NegotiateContextOffset (the offset "to
   --    the first, 8-byte-aligned negotiate context"),
   --    NegotiateContextCount and Reserved2 ("The client MUST set this to
   --    0"); otherwise ClientStartTime, which "The client MUST set ... to
   --    0";
   --  * Dialects from offset 36, at least one of them a known one.
   --  What follows the dialects, the padding and the contexts, is stated
   --  apart.
   function Is_Negotiate_Request
     (Data : SMB.Bytes;
      Request : Negotiate_Request;
      Client_Guid : SMB.Bytes;
      Dialects : Word_List) return Boolean is
     (Data'Length >= Negotiate_Request_Size
      and then Dialects'Length > 0
      and then SMB.Spec.Encoding.LE16 (Data, 0) = Negotiate_Request_Size
      and then SMB.Spec.Encoding.LE16 (Data, 2) = Request.Dialect_Count
      and then Natural (Request.Dialect_Count) = Dialects'Length
      and then SMB.Spec.Encoding.LE16 (Data, 4) = Request.Security_Mode
      and then SMB.Spec.Encoding.LE16 (Data, 6) = 0
      and then SMB.Spec.Encoding.LE32 (Data, 8) = Request.Capabilities
      and then Client_Guid'Length = 16
      and then Has_Bytes (Data, 12, Client_Guid)
      and then (for some Dialect of Dialects => Is_Known_Dialect (Dialect))
      and then
        (if Offers_0311 (Dialects) then
           SMB.Spec.Encoding.LE32 (Data, 28) =
             Request.Negotiate_Context_Offset
           and then Request.Negotiate_Context_Offset mod 8 = 0
           and then SMB.Spec.Encoding.LE16 (Data, 32) =
             Request.Negotiate_Context_Count
           and then SMB.Spec.Encoding.LE16 (Data, 34) = 0
         else SMB.Spec.Encoding.LE64 (Data, 28) = 0)
      and then Has_Words (Data, Negotiate_Request_Size, Dialects))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Client_Guid'Length <= SMB.Maximum_Frame_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");

   --  The body offset of the first negotiate context after Count dialects.
   --  2.2.3: Padding is "Optional padding between the end of the Dialects
   --  array and the first negotiate context ... so that the first negotiate
   --  context is 8-byte aligned", and 3.2.4.2.2.2 adds padding "to make the
   --  next field 8-byte aligned". The header is 64 bytes, so an offset is
   --  aligned counted from the header exactly when it is counted from the
   --  body.
   function First_Context (Count : Natural) return Natural is
     (Align_8 (Negotiate_Request_Size + 2 * Count))
   with Pre => Count <= SMB.Maximum_Frame_Size / 4;

   --  2.2.3.1: the context types.
   Preauth_Integrity_Capabilities : constant SMB.Word := 16#0001#;
   Encryption_Capabilities : constant SMB.Word := 16#0002#;
   Compression_Capabilities : constant SMB.Word := 16#0003#;
   Netname_Negotiate_Context_Id : constant SMB.Word := 16#0005#;
   Transport_Capabilities : constant SMB.Word := 16#0006#;
   RDMA_Transform_Capabilities : constant SMB.Word := 16#0007#;
   Signing_Capabilities : constant SMB.Word := 16#0008#;

   --  ContextType, DataLength and Reserved come before Data.
   Context_Header_Size : constant := 8;

   --  2.2.3.1: a negotiate context at body offset Position, of
   --  Context_Type, with DataLength "The length, in bytes, of the Data
   --  field" and Reserved, which "MUST be set to 0 by the client". Its Data
   --  is Context_Data (each context this client sends has some).
   function Is_Negotiate_Context
     (Data : SMB.Bytes;
      Position : Natural;
      Context_Type : SMB.Word;
      Data_Length : Natural) return Boolean is
     (Position <= Data'Length
      and then Context_Header_Size <= Data'Length - Position
      and then Data_Length <= Data'Length - Position - Context_Header_Size
      and then SMB.Spec.Encoding.LE16 (Data, Position) = Context_Type
      and then Natural (SMB.Spec.Encoding.LE16 (Data, Position + 2)) =
        Data_Length
      and then SMB.Spec.Encoding.LE32 (Data, Position + 4) = 0)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   function Context_Data
     (Data : SMB.Bytes; Position, Data_Length : Natural) return SMB.Bytes is
     (Data (Data'First + (Position + Context_Header_Size)
            .. Data'First
               + (Position + Context_Header_Size + Data_Length - 1)))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Position <= Data'Length
     and then Context_Header_Size <= Data'Length - Position
     and then Data_Length > 0
     and then Data_Length <= Data'Length - Position - Context_Header_Size,
     Post => Context_Data'Result'Length = Data_Length;

   --  2.2.3: "Subsequent negotiate contexts MUST appear at the first
   --  8-byte-aligned offset following the previous negotiate context": the
   --  body offset of the context after the one at Position with Data_Length
   --  bytes of data.
   function Next_Context (Position, Data_Length : Natural) return Natural is
     (Align_8 (Position + Context_Header_Size + Data_Length))
   with Pre =>
     Position <= SMB.Maximum_Frame_Size
     and then Data_Length <=
       SMB.Maximum_Frame_Size - Position - Context_Header_Size;

   --  The predicates on a context's data below take the data to be exactly
   --  its fields: DataLength is "The length, in bytes, of the Data field",
   --  and this client sends no more. (A receiver's check would read the
   --  fields from a longer Data too.)

   --  2.2.3.1.1: SMB2_PREAUTH_INTEGRITY_CAPABILITIES: HashAlgorithmCount,
   --  "MUST be greater than zero"; SaltLength, "The size, in bytes, of the
   --  Salt field"; HashAlgorithms; Salt.
   SHA_512 : constant SMB.Word := 16#0001#;

   function Is_Preauth_Integrity_Capabilities
     (Data : SMB.Bytes; Hash_Algorithms : Word_List; Salt : SMB.Bytes)
      return Boolean is
     (Hash_Algorithms'Length > 0
      and then Data'Length >= 4
      and then Natural (SMB.Spec.Encoding.LE16 (Data, 0)) =
        Hash_Algorithms'Length
      and then Natural (SMB.Spec.Encoding.LE16 (Data, 2)) = Salt'Length
      and then Has_Words (Data, 4, Hash_Algorithms)
      and then Has_Bytes (Data, 4 + 2 * Hash_Algorithms'Length, Salt)
      and then Data'Length = 4 + 2 * Hash_Algorithms'Length + Salt'Length)
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Salt'Length <= SMB.Maximum_Frame_Size;

   --  2.2.3.1.2: SMB2_ENCRYPTION_CAPABILITIES: CipherCount, "MUST be
   --  greater than zero", then Ciphers, "the most preferred cipher ... at
   --  the beginning of the array".
   AES_128_CCM : constant SMB.Word := 16#0001#;
   AES_128_GCM : constant SMB.Word := 16#0002#;
   AES_256_CCM : constant SMB.Word := 16#0003#;
   AES_256_GCM : constant SMB.Word := 16#0004#;

   function Is_Encryption_Capabilities
     (Data : SMB.Bytes; Ciphers : Word_List) return Boolean is
     (Ciphers'Length > 0
      and then Data'Length >= 2
      and then Natural (SMB.Spec.Encoding.LE16 (Data, 0)) = Ciphers'Length
      and then Has_Words (Data, 2, Ciphers)
      and then Data'Length = 2 + 2 * Ciphers'Length)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   --  2.2.3.1.7: SMB2_SIGNING_CAPABILITIES: SigningAlgorithmCount, "MUST be
   --  greater than zero", then SigningAlgorithms, the most preferred first.
   HMAC_SHA256 : constant SMB.Word := 16#0000#;
   AES_CMAC : constant SMB.Word := 16#0001#;
   AES_GMAC : constant SMB.Word := 16#0002#;

   function Is_Signing_Capabilities
     (Data : SMB.Bytes; Signing_Algorithms : Word_List) return Boolean is
     (Signing_Algorithms'Length > 0
      and then Data'Length >= 2
      and then Natural (SMB.Spec.Encoding.LE16 (Data, 0)) =
        Signing_Algorithms'Length
      and then Has_Words (Data, 2, Signing_Algorithms)
      and then Data'Length = 2 + 2 * Signing_Algorithms'Length)
   with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   --  This client's request (3.2.4.2.2.2, and the profile in
   --  docs/smb3-design.md).
   --  * Dialects: "If the application has provided SpecifiedDialects", they
   --    are the request's. This client's caller requires 3.1.1 or allows
   --    2.1 too, so they are 0x0311, then 0x0210 when allowed.
   --  * SecurityMode: signing is always required ("If RequireMessageSigning
   --    is TRUE, the client MUST set the SMB2_NEGOTIATE_SIGNING_REQUIRED
   --    bit"), and the enabled bit, which "The server MUST ignore", is set
   --    too.
   --  * Capabilities: SMB2_GLOBAL_CAP_ENCRYPTION, which the client "SHOULD
   --    set" when "MaxDialect is 3.1.1, IsEncryptionSupported is TRUE"; and
   --    SMB2_GLOBAL_CAP_LARGE_MTU, as the client "supports multi-credit
   --    operations" (2.2.3). No other: no DFS, leasing, multichannel,
   --    persistent handles, directory leasing or notifications.
   --  * The contexts: SMB2_PREAUTH_INTEGRITY_CAPABILITIES first, as
   --    NegotiateContextOffset is set "to the offset of the SMB2
   --    NEGOTIATE_CONTEXT added above"; then, as IsEncryptionSupported,
   --    SMB2_ENCRYPTION_CAPABILITIES with "the ciphers supported by the
   --    client ... in the order of preference"; then, as
   --    IsSigningCapabilitiesSupported, SMB2_SIGNING_CAPABILITIES. No
   --    compression, RDMA, NETNAME (a SHOULD) or transport context.
   function Client_Dialects (Allow_21 : Boolean) return Word_List is
     (if Allow_21 then Word_List'(Dialect_0311, Dialect_0210)
      else Word_List'(0 => Dialect_0311))
   with Post =>
     Client_Dialects'Result'First = 0
     and then Client_Dialects'Result'Length = (if Allow_21 then 2 else 1);

   Client_Context_Count : constant := 3;

   function Client_Negotiate (Allow_21 : Boolean) return Negotiate_Request is
     (Dialect_Count => (if Allow_21 then 2 else 1),
      Security_Mode => Signing_Enabled + Signing_Required,
      Capabilities => Global_Cap_Large_MTU + Global_Cap_Encryption,
      Negotiate_Context_Offset =>
        SMB.DWord
          (Header_Size + First_Context (Client_Dialects (Allow_21)'Length)),
      Negotiate_Context_Count => Client_Context_Count);

   --  SHA-512, the one hash algorithm 2.2.3.1.1 defines. The salt "SHOULD
   --  be initialized to an implementation-specific number of bytes generated
   --  for this request by a cryptographically secure pseudo-random number
   --  generator"; Windows sends 32 (footnote 134), and so does this client.
   Client_Hash_Algorithms : constant Word_List := (0 => SHA_512);
   Client_Salt_Size : constant := 32;

   --  As a Windows client orders them by default: AES-128 first, GCM
   --  before CCM.
   Client_Ciphers : constant Word_List :=
     (AES_128_GCM, AES_128_CCM, AES_256_GCM, AES_256_CCM);

   Client_Signing_Algorithms : constant Word_List := (AES_GMAC, AES_CMAC);

   --  The request: the fields and the dialects; the three contexts, each
   --  at the offset 2.2.3 requires, with the data above; and nothing after
   --  the last. The standard leaves the padding's value open; this
   --  client's is zero.
   function Is_Client_Negotiate_Request
     (Data : SMB.Bytes;
      Client_Guid : SMB.Bytes;
      Salt : SMB.Bytes;
      Allow_21 : Boolean) return Boolean is
     (declare
        Dialects : constant Word_List := Client_Dialects (Allow_21);
        Preauth_At : constant Natural := First_Context (Dialects'Length);
        Preauth_Length : constant Natural :=
          4 + 2 * Client_Hash_Algorithms'Length + Salt'Length;
        Encryption_At : constant Natural :=
          Next_Context (Preauth_At, Preauth_Length);
        Encryption_Length : constant Natural := 2 + 2 * Client_Ciphers'Length;
        Signing_At : constant Natural :=
          Next_Context (Encryption_At, Encryption_Length);
        Signing_Length : constant Natural :=
          2 + 2 * Client_Signing_Algorithms'Length;
      begin
        Data'Length = Signing_At + Context_Header_Size + Signing_Length
        and then Is_Negotiate_Request
          (Data, Client_Negotiate (Allow_21), Client_Guid, Dialects)
        and then Is_Zero
          (Data, Negotiate_Request_Size + 2 * Dialects'Length, Preauth_At)
        and then Is_Negotiate_Context
          (Data, Preauth_At, Preauth_Integrity_Capabilities, Preauth_Length)
        and then Is_Preauth_Integrity_Capabilities
          (Context_Data (Data, Preauth_At, Preauth_Length),
           Client_Hash_Algorithms, Salt)
        and then Is_Zero
          (Data, Preauth_At + Context_Header_Size + Preauth_Length,
           Encryption_At)
        and then Is_Negotiate_Context
          (Data, Encryption_At, Encryption_Capabilities, Encryption_Length)
        and then Is_Encryption_Capabilities
          (Context_Data (Data, Encryption_At, Encryption_Length),
           Client_Ciphers)
        and then Is_Zero
          (Data, Encryption_At + Context_Header_Size + Encryption_Length,
           Signing_At)
        and then Is_Negotiate_Context
          (Data, Signing_At, Signing_Capabilities, Signing_Length)
        and then Is_Signing_Capabilities
          (Context_Data (Data, Signing_At, Signing_Length),
           Client_Signing_Algorithms))
   with Pre =>
     Data'Length <= SMB.Maximum_Frame_Size
     and then Client_Guid'Length <= SMB.Maximum_Frame_Size
     and then Salt'Length = Client_Salt_Size,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body");
end SMB.Spec.SMB2.Negotiation;
