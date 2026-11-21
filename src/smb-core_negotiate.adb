with SMB.Core_Wire;

package body SMB.Core_Negotiate is
   pragma SPARK_Mode (On);

   package N renames SMB.Spec.SMB2.Negotiation with Ghost;

   --  The request is built from its four parts, each stated against the
   --  specification on its own, then the whole: as one goal, the
   --  postcondition took the provers about a minute, near their time limit
   --  on GitHub's runners, and assertions on one long concatenation did not
   --  prove. The assertions run once a connection.
   function Request
     (Guid : Guid_Bytes; Salt : Salt_Bytes; Allow_21 : Boolean)
      return Request_Bytes
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         N.Is_Client_Negotiate_Request);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         N.Is_Negotiate_Request);
      --  The fields and the dialects, with the padding to the first
      --  context: 40 bytes.
      Fields : constant SMB.Bytes (0 .. 39) :=
        LE16 (36)
        & LE16 (if Allow_21 then 2 else 1)
        & LE16 (3)
        & LE16 (0)
        & LE16 (16#44#) & Zero_High
        & Guid
        & LE16 (Request_Context_Offset) & Zero_High
        & LE16 (Request_Context_Count)
        & LE16 (0)
        & LE16 (SMB.SMB2_Dialect_0311)
        --  The second dialect, or padding to the first context.
        & LE16 (if Allow_21 then SMB.SMB2_Dialect_0210 else 0);
      --  PREAUTH_INTEGRITY_CAPABILITIES: one hash algorithm, the salt's
      --  length, SHA-512 and the salt, then padding to the next context.
      Preauth : constant SMB.Bytes (0 .. 47) :=
        LE16 (Preauth_Integrity)
        & LE16 (6 + Salt_Bytes'Length)
        & LE16 (0) & Zero_High
        & LE16 (1)
        & LE16 (Salt_Bytes'Length)
        & LE16 (SHA_512)
        & Salt
        & LE16 (0);
      --  ENCRYPTION_CAPABILITIES: four ciphers, AES-128 first, GCM before
      --  CCM, then padding to the next context.
      Encryption_Part : constant SMB.Bytes (0 .. 23) :=
        LE16 (Encryption)
        & LE16 (10)
        & LE16 (0) & Zero_High
        & LE16 (4)
        & LE16 (GCM_Id)
        & LE16 (CCM_Id)
        & LE16 (GCM_256_Id)
        & LE16 (CCM_256_Id)
        & LE16 (0) & Zero_High & LE16 (0);
      --  SIGNING_CAPABILITIES: two algorithms, AES-GMAC first.
      Signing : constant SMB.Bytes (0 .. 13) :=
        LE16 (Signing_Capabilities)
        & LE16 (6)
        & LE16 (0) & Zero_High
        & LE16 (2)
        & LE16 (GMAC_Id)
        & LE16 (CMAC_Id);
      Result : constant Request_Bytes :=
        Fields & Preauth & Encryption_Part & Signing;
   begin
      --  Each part on its own. The first dialect is 3.1.1: the witness of
      --  the two "for some" in Is_Negotiate_Request.
      pragma Assert
        (N.Client_Dialects (Allow_21) (0) = N.Dialect_0311
         and then N.Offers_0311 (N.Client_Dialects (Allow_21))
         and then N.Is_Known_Dialect (N.Client_Dialects (Allow_21) (0)));
      pragma Assert
        (N.Is_Negotiate_Context
           (Preauth, 0, N.Preauth_Integrity_Capabilities, 38)
         and then N.Is_Preauth_Integrity_Capabilities
           (N.Context_Data (Preauth, 0, 38), N.Client_Hash_Algorithms, Salt)
         and then N.Is_Zero (Preauth, 46, 48));
      pragma Assert
        (N.Is_Negotiate_Context
           (Encryption_Part, 0, N.Encryption_Capabilities, 10)
         and then N.Is_Encryption_Capabilities
           (N.Context_Data (Encryption_Part, 0, 10), N.Client_Ciphers)
         and then N.Is_Zero (Encryption_Part, 18, 24));
      pragma Assert
        (N.Is_Negotiate_Context (Signing, 0, N.Signing_Capabilities, 6)
         and then N.Is_Signing_Capabilities
           (N.Context_Data (Signing, 0, 6), N.Client_Signing_Algorithms));
      --  Where they sit in the request. The fields are stated on the request
      --  itself, which the provers find faster than on the part.
      pragma Assert
        (for all I in 0 .. 39 => Result (I) = Fields (I));
      pragma Assert
        (N.Is_Negotiate_Request
           (Result, N.Client_Negotiate (Allow_21), Guid,
            N.Client_Dialects (Allow_21)));
      pragma Assert
        (N.Is_Zero
           (Result,
            N.Negotiate_Request_Size + 2 * N.Client_Dialects (Allow_21)'Length,
            40));
      pragma Assert
        (for all I in 0 .. 47 => Result (40 + I) = Preauth (I));
      pragma Assert
        (for all I in 0 .. 23 => Result (88 + I) = Encryption_Part (I));
      pragma Assert
        (for all I in 0 .. 13 => Result (112 + I) = Signing (I));
      --  The contexts in the request, from their parts.
      pragma Assert
        (N.Is_Negotiate_Context
           (Result, 40, N.Preauth_Integrity_Capabilities, 38));
      pragma Assert (for all I in 0 .. 31 => Result (54 + I) = Salt (I));
      pragma Assert
        (N.Is_Preauth_Integrity_Capabilities
           (N.Context_Data (Result, 40, 38), N.Client_Hash_Algorithms, Salt));
      pragma Assert
        (N.Is_Negotiate_Context
           (Result, 88, N.Encryption_Capabilities, 10)
         and then N.Is_Encryption_Capabilities
           (N.Context_Data (Result, 88, 10), N.Client_Ciphers));
      pragma Assert
        (N.Is_Negotiate_Context (Result, 112, N.Signing_Capabilities, 6)
         and then N.Is_Signing_Capabilities
           (N.Context_Data (Result, 112, 6), N.Client_Signing_Algorithms));
      pragma Assert
        (N.First_Context (N.Client_Dialects (Allow_21)'Length) = 40
         and then N.Next_Context (40, 38) = 88
         and then N.Next_Context (88, 10) = 112);
      --  The padding between the contexts, in the request.
      pragma Assert
        (Result (86) = 0 and then Result (87) = 0
         and then (for all I in 106 .. 111 => Result (I) = 0));
      pragma Assert
        (N.Is_Zero (Result, 86, 88) and then N.Is_Zero (Result, 106, 112));
      return Result;
   end Request;

   use type SMB.DWord;

   --  The context types we never offer (MS-SMB2 2.2.3.1).
   Compression : constant SMB.Word := 3;
   Transport : constant SMB.Word := 6;
   RDMA_Transform : constant SMB.Word := 7;

   --  The NEGOTIATE response's fixed part: 64 header bytes and 64 body
   --  bytes, with NegotiateContextCount at body offset 6 and
   --  NegotiateContextOffset at body offset 60.
   Fixed_Response_Length : constant := 128;
   Count_Offset : constant := 64 + 6;
   First_Context_Offset : constant := 64 + 60;

   procedure Check_Response_Contexts
     (Packet : SMB.Bytes;
      Cipher : out Cipher_Id;
      Signing : out SMB3_Signing_Id;
      Status : out SMB.Core_Status)
   is
      Count : SMB.Word;
      First : SMB.DWord;
      Position : Natural;
      Data : Natural;
      Kind : SMB.Word;
      Length : Natural;
      Selected : Cipher_Id := No_Cipher;
      Chosen : SMB3_Signing_Id := AES_CMAC;
      Seen_Preauth : Boolean := False;
      Seen_Encryption : Boolean := False;
      Seen_Signing : Boolean := False;
   begin
      Cipher := No_Cipher;
      Signing := AES_CMAC;
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
               when CCM_256_Id => Selected := AES_256_CCM;
               when GCM_256_Id => Selected := AES_256_GCM;
               when others =>
                  Status := SMB.Invalid_Protocol;
                  return;
            end case;
            Seen_Encryption := True;
         elsif Kind = Signing_Capabilities then
            --  SigningAlgorithmCount, then the algorithms.
            if Seen_Signing
              or else Length < 4
              or else SMB.Core_Wire.Encoded_U16 (Packet, Data) /= 1
            then
               Status := SMB.Invalid_Protocol;
               return;
            end if;
            case SMB.Core_Wire.Encoded_U16 (Packet, Data + 2) is
               --  Chosen is already AES_CMAC, as without a signing context.
               when CMAC_Id => null;
               when GMAC_Id => Chosen := AES_GMAC;
               when others =>
                  Status := SMB.Invalid_Protocol;
                  return;
            end case;
            Seen_Signing := True;
         elsif Kind = Compression
           or else Kind = Transport
           or else Kind = RDMA_Transform
         then
            Status := SMB.Invalid_Protocol;
            return;
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
      Signing := Chosen;
      Status := SMB.Ok;
   end Check_Response_Contexts;

end SMB.Core_Negotiate;
