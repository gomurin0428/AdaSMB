with SMB.Core_Wire;

package body SMB.Core_Negotiate is
   pragma SPARK_Mode (On);

   use type SMB.Word;
   use type SMB.DWord;

   subtype Two_Bytes is SMB.Bytes (0 .. 1);

   function LE16 (Value : SMB.Word) return Two_Bytes is
     (SMB.Byte (Value mod 2**8), SMB.Byte (Value / 2**8))
     with Post => True;

   --  The request's four-byte fields all hold values below 2**16, so each is
   --  written as LE16 of the value and two zero bytes.
   Zero_High : constant Two_Bytes := (0, 0);

   --  Negotiate context types (MS-SMB2 2.2.3.1).
   Preauth_Integrity : constant SMB.Word := 1;
   Encryption : constant SMB.Word := 2;
   Compression : constant SMB.Word := 3;
   Transport : constant SMB.Word := 6;
   RDMA_Transform : constant SMB.Word := 7;
   Signing : constant SMB.Word := 8;

   SHA_512 : constant SMB.Word := 1;
   CCM_Id : constant SMB.Word := 1;
   GCM_Id : constant SMB.Word := 2;

   --  The NEGOTIATE response's fixed part: 64 header bytes and 64 body
   --  bytes, with NegotiateContextCount at body offset 6 and
   --  NegotiateContextOffset at body offset 60.
   Fixed_Response_Length : constant := 128;
   Count_Offset : constant := 64 + 6;
   First_Context_Offset : constant := 64 + 60;

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
      --  ENCRYPTION_CAPABILITIES: two ciphers, GCM first.
      & LE16 (Encryption)
      & LE16 (6)
      & LE16 (0) & Zero_High
      & LE16 (2)
      & LE16 (GCM_Id)
      & LE16 (CCM_Id));

   procedure Check_Response_Contexts
     (Packet : SMB.Bytes;
      Cipher : out Cipher_Id;
      Status : out SMB.Core_Status)
   is
      Count : SMB.Word;
      First : SMB.DWord;
      Position : Natural;
      Data : Natural;
      Kind : SMB.Word;
      Length : Natural;
      Selected : Cipher_Id := No_Cipher;
      Seen_Preauth : Boolean := False;
      Seen_Encryption : Boolean := False;
      Seen_Compression : Boolean := False;
      Seen_Transport : Boolean := False;
      Seen_RDMA : Boolean := False;
   begin
      Cipher := No_Cipher;
      if Packet'Length < Fixed_Response_Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Count := SMB.Core_Wire.Encoded_U16 (Packet, Count_Offset);
      First := SMB.Core_Wire.Encoded_U32 (Packet, First_Context_Offset);
      --  The first context's header must fit; without contexts there is no
      --  preauth context, which fails below.
      if First < Fixed_Response_Length
        or else First mod 8 /= 0
        or else First > SMB.DWord (Packet'Length - 8)
      then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Position := Natural (First);
      for Index in 1 .. Count loop
         pragma Loop_Invariant (Position + 8 <= Packet'Length);
         --  Each context: Type (2), DataLength (2), Reserved (4), then data.
         Kind := SMB.Core_Wire.Encoded_U16 (Packet, Position);
         Length := Natural (SMB.Core_Wire.Encoded_U16 (Packet, Position + 2));
         Data := Position + 8;
         if Data + Length > Packet'Length then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         if Kind = Preauth_Integrity then
            --  HashAlgorithmCount, SaltLength, the algorithms, the salt.
            if Seen_Preauth
              or else Length < 6
              or else SMB.Core_Wire.Encoded_U16 (Packet, Data) /= 1
              or else SMB.Core_Wire.Encoded_U16 (Packet, Data + 4) /= SHA_512
              or else Natural (SMB.Core_Wire.Encoded_U16 (Packet, Data + 2))
                > Length - 6
            then
               Status := SMB.Invalid_Protocol;
               return;
            end if;
            Seen_Preauth := True;
         elsif Kind = Encryption then
            --  CipherCount, then the ciphers.
            if Seen_Encryption
              or else Length < 4
              or else SMB.Core_Wire.Encoded_U16 (Packet, Data) /= 1
            then
               Status := SMB.Invalid_Protocol;
               return;
            end if;
            case SMB.Core_Wire.Encoded_U16 (Packet, Data + 2) is
               when 0 => null;
               when CCM_Id => Selected := AES_128_CCM;
               when GCM_Id => Selected := AES_128_GCM;
               when others =>
                  Status := SMB.Invalid_Protocol;
                  return;
            end case;
            Seen_Encryption := True;
         elsif Kind = Signing
           or else (Kind = Compression and then Seen_Compression)
           or else (Kind = Transport and then Seen_Transport)
           or else (Kind = RDMA_Transform and then Seen_RDMA)
         then
            Status := SMB.Invalid_Protocol;
            return;
         else
            Seen_Compression := Seen_Compression or else Kind = Compression;
            Seen_Transport := Seen_Transport or else Kind = Transport;
            Seen_RDMA := Seen_RDMA or else Kind = RDMA_Transform;
         end if;
         --  The next context starts at the next 8-byte boundary, and its
         --  header must fit too.
         if Index < Count then
            Position := (Data + Length + 7) / 8 * 8;
            if Position + 8 > Packet'Length then
               Status := SMB.Invalid_Offset;
               return;
            end if;
         end if;
      end loop;
      if not Seen_Preauth then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Cipher := Selected;
      Status := SMB.Ok;
   end Check_Response_Contexts;

end SMB.Core_Negotiate;
