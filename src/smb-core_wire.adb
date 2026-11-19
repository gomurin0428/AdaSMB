with SMB.AES.CMAC;
with SMB.Crypto;

package body SMB.Core_Wire with SPARK_Mode is
   --  The eight bytes of a value, put back in their places, give the value.
   --  Proved on its own, as a pure bit-vector identity, so that Write_U64's
   --  postcondition does not have to find it inside a larger goal.
   procedure Lemma_U64_Bytes (Value : SMB.QWord)
   with Ghost,
     Post =>
       (SMB.QWord (U64_Byte (Value, 0))
        or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 1)), 8)
        or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 2)), 16)
        or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 3)), 24)
        or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 4)), 32)
        or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 5)), 40)
        or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 6)), 48)
        or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 7)), 56))
       = Value
   is
   begin
      null;
   end Lemma_U64_Bytes;

   procedure Read_U16
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.Word;
      Status : out SMB.Core_Status) is
   begin
      Value := 0;
      if Offset > Data'Length or else Data'Length - Offset < 2 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Value :=
        SMB.Word (Data (Data'First + Offset))
        or Interfaces.Shift_Left
          (SMB.Word (Data (Data'First + Offset + 1)), 8);
      Status := SMB.Ok;
   end Read_U16;

   procedure Read_U32
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.DWord;
      Status : out SMB.Core_Status) is
   begin
      Value := 0;
      if Offset > Data'Length or else Data'Length - Offset < 4 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Value :=
        SMB.DWord (Data (Data'First + Offset))
        or Interfaces.Shift_Left
          (SMB.DWord (Data (Data'First + Offset + 1)), 8)
        or Interfaces.Shift_Left
          (SMB.DWord (Data (Data'First + Offset + 2)), 16)
        or Interfaces.Shift_Left
          (SMB.DWord (Data (Data'First + Offset + 3)), 24);
      Status := SMB.Ok;
   end Read_U32;

   procedure Read_U64
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.QWord;
      Status : out SMB.Core_Status) is
   begin
      Value := 0;
      if Offset > Data'Length or else Data'Length - Offset < 8 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Value :=
        SMB.QWord (Data (Data'First + Offset))
        or Interfaces.Shift_Left
          (SMB.QWord (Data (Data'First + Offset + 1)), 8)
        or Interfaces.Shift_Left
          (SMB.QWord (Data (Data'First + Offset + 2)), 16)
        or Interfaces.Shift_Left
          (SMB.QWord (Data (Data'First + Offset + 3)), 24)
        or Interfaces.Shift_Left
          (SMB.QWord (Data (Data'First + Offset + 4)), 32)
        or Interfaces.Shift_Left
          (SMB.QWord (Data (Data'First + Offset + 5)), 40)
        or Interfaces.Shift_Left
          (SMB.QWord (Data (Data'First + Offset + 6)), 48)
        or Interfaces.Shift_Left
          (SMB.QWord (Data (Data'First + Offset + 7)), 56);
      Status := SMB.Ok;
   end Read_U64;

   procedure Write_U16
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.Word;
      Status : out SMB.Core_Status) is
   begin
      if Offset > Data'Length or else Data'Length - Offset < 2 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Data (Data'First + Offset) := SMB.Byte (Value and 16#FF#);
      Data (Data'First + Offset + 1) :=
        SMB.Byte (Interfaces.Shift_Right (Value, 8));
      Status := SMB.Ok;
   end Write_U16;

   procedure Write_U32
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.DWord;
      Status : out SMB.Core_Status) is
   begin
      if Offset > Data'Length or else Data'Length - Offset < 4 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      for I in 0 .. 3 loop
         Data (Data'First + Offset + I) :=
           SMB.Byte
             (Interfaces.Shift_Right (Value, I * 8) and 16#FF#);
      end loop;
      Status := SMB.Ok;
   end Write_U32;

   procedure Write_U64
     (Data : in out SMB.Bytes; Offset : Natural; Value : SMB.QWord;
      Status : out SMB.Core_Status) is
   begin
      if Offset > Data'Length or else Data'Length - Offset < 8 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      --  No loop invariant: GNATprove unrolls a loop this short, and an
      --  invariant over the whole of Data would be checked at run time on
      --  every byte of the packet, eight times.
      for I in 0 .. 7 loop
         Data (Data'First + Offset + I) :=
           SMB.Byte
             (Interfaces.Shift_Right (Value, I * 8) and 16#FF#);
      end loop;
      Lemma_U64_Bytes (Value);
      pragma Assert
        (Encoded_U64 (Data, Offset) =
           (SMB.QWord (U64_Byte (Value, 0))
            or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 1)), 8)
            or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 2)), 16)
            or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 3)), 24)
            or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 4)), 32)
            or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 5)), 40)
            or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 6)), 48)
            or Interfaces.Shift_Left (SMB.QWord (U64_Byte (Value, 7)), 56)));
      Status := SMB.Ok;
   end Write_U64;

   function Header_Nt_Status (Data : SMB.Bytes) return SMB.DWord is
     (SMB.DWord (Data (Data'First + 8))
      or Interfaces.Shift_Left (SMB.DWord (Data (Data'First + 9)), 8)
      or Interfaces.Shift_Left (SMB.DWord (Data (Data'First + 10)), 16)
      or Interfaces.Shift_Left (SMB.DWord (Data (Data'First + 11)), 24));

   procedure Initialize_Header
     (Data : in out SMB.Bytes;
      Command : Command_Code;
      Message_Id : SMB.QWord;
      Tree_Id : SMB.DWord;
      Session_Id : SMB.QWord;
      Credit : SMB.Word;
      Status : out SMB.Core_Status;
      Charge : SMB.Word := 1) is
      Field_Status : SMB.Core_Status;

      --  What the zero fill and ProtocolId leave, which no field write
      --  changes: ProtocolId, Status, Flags, NextCommand, Reserved and the
      --  Signature. Checked after each write, so that each check follows
      --  from one write's frame.
      function Fixed_Fields_Hold return Boolean is
        (Data'Length >= Header_Size
         and then Data (Data'First) = 16#FE#
         and then Data (Data'First + 1) = 16#53#
         and then Data (Data'First + 2) = 16#4D#
         and then Data (Data'First + 3) = 16#42#
         and then Encoded_U32 (Data, 8) = 0
         and then Encoded_U32 (Data, 16) = 0
         and then Encoded_U32 (Data, 20) = 0
         and then Encoded_U32 (Data, 32) = 0
         and then
           (for all Index in 48 .. 63 => Data (Data'First + Index) = 0))
      with Ghost, Pre => Data'Length <= SMB.Maximum_Frame_Size;
   begin
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Data (Data'First .. Data'Last - (Data'Length - Header_Size)) :=
        (others => 0);
      Data (Data'First .. Data'First + 3) :=
        (16#FE#, 16#53#, 16#4D#, 16#42#);
      pragma Assert (Fixed_Fields_Hold);
      --  The buffer holds a whole header, so every field write succeeds.
      Write_U16 (Data, 4, Header_Size, Field_Status);
      pragma Assert (Field_Status = SMB.Ok);
      pragma Assert (Fixed_Fields_Hold);
      Write_U16 (Data, 6, Charge, Field_Status);
      pragma Assert (Field_Status = SMB.Ok);
      pragma Assert (Fixed_Fields_Hold);
      Write_U16 (Data, 12, SMB.Word (Command), Field_Status);
      pragma Assert (Field_Status = SMB.Ok);
      pragma Assert (Fixed_Fields_Hold);
      Write_U16 (Data, 14, Credit, Field_Status);
      pragma Assert (Field_Status = SMB.Ok);
      pragma Assert (Fixed_Fields_Hold);
      Write_U64 (Data, 24, Message_Id, Field_Status);
      pragma Assert (Field_Status = SMB.Ok);
      pragma Assert (Fixed_Fields_Hold);
      Write_U32 (Data, 36, Tree_Id, Field_Status);
      pragma Assert (Field_Status = SMB.Ok);
      pragma Assert (Fixed_Fields_Hold);
      Write_U64 (Data, 40, Session_Id, Status);
      pragma Assert (Fixed_Fields_Hold);
   end Initialize_Header;

   procedure Validate_Header
     (Data : SMB.Bytes;
      Expected : Expected_Header;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status;
      Async_Id : SMB.QWord := 0;
      Interim : Boolean := False) is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Command : SMB.Word;
      Credit : SMB.Word;
      Flags : SMB.DWord;
      Message_Id : SMB.QWord;
      Tree_Id : SMB.DWord;
      Session_Id : SMB.QWord;
      Signature_Zero : Boolean := True;
   begin
      Nt_Status := 0;
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if Data (Data'First) /= 16#FE#
        or else Data (Data'First + 1) /= 16#53#
        or else Data (Data'First + 2) /= 16#4D#
        or else Data (Data'First + 3) /= 16#42#
      then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      --  The header is at least Header_Size bytes long, so every field below
      --  can be read without a status.
      if Encoded_U16 (Data, 4) /= Header_Size then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Command := Encoded_U16 (Data, 12);
      Credit := Encoded_U16 (Data, 14);
      if (Async_Id = 0 and then Credit = 0)
        or else (Async_Id /= 0 and then not Interim and then Credit /= 0)
      then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Flags := Encoded_U32 (Data, 16);
      if Encoded_U32 (Data, 20) /= 0 then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Message_Id := Encoded_U64 (Data, 24);
      Tree_Id := Encoded_U32 (Data, 36);
      Session_Id := Encoded_U64 (Data, 40);
      if (Flags and 1) = 0
        or else ((Flags and 2) /= 0) /= (Interim or Async_Id /= 0)
      then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      if Interim /= (Header_Nt_Status (Data) = SMB.Status_Pending) then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      if Interim or Async_Id /= 0 then
         if Encoded_U64 (Data, 32) = 0
           or else (Async_Id /= 0 and then Encoded_U64 (Data, 32) /= Async_Id)
         then
            Status := SMB.Correlation_Error;
            return;
         end if;
      end if;
      if Command /= SMB.Word (Expected.Command)
        or else Message_Id /= Expected.Message_Id
        or else (Expected.Match_Tree and then not Interim and then Async_Id = 0
                 and then Tree_Id /= Expected.Tree_Id)
        or else (Expected.Match_Session and then Session_Id /= Expected.Session_Id)
      then
         Status := SMB.Correlation_Error;
         return;
      end if;
      for Index in 48 .. 63 loop
         Signature_Zero :=
           Signature_Zero and then Data (Data'First + Index) = 0;
         pragma Loop_Invariant
           (Signature_Zero =
              (for all I in 48 .. Index => Data (Data'First + I) = 0));
      end loop;
      if Interim then
         null;
      elsif Expected.Signed then
         if (Flags and 8) = 0 then
            Status := SMB.Signature_Error;
            return;
         end if;
      elsif (Flags and 8) /= 0 or else not Signature_Zero then
         Status := SMB.Signature_Error;
         return;
      end if;
      Nt_Status := Header_Nt_Status (Data);
      Status := SMB.Ok;
   end Validate_Header;

   procedure Sign
     (Data : in out SMB.Bytes;
      Key : SMB.Bytes;
      Status : out SMB.Core_Status) is
   begin
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if Key'Length = 0 then
         Status := SMB.Invalid_Value;
         return;
      end if;
      for Index in 48 .. 63 loop
         Data (Data'First + Index) := 0;
      end loop;
      declare
         Signature : Signature_Bytes;
      begin
         Compute_Signature (Data, Key, Signature, Status);
         Data (Data'First + 48 .. Data'First + 63) := Signature;
      end;
   end Sign;

   procedure Compute_Signature
     (Data : SMB.Bytes;
      Key : SMB.Bytes;
      Signature : out Signature_Bytes;
      Status : out SMB.Core_Status) is
   begin
      Signature := (others => 0);
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if Key'Length = 0 then
         Status := SMB.Invalid_Value;
         return;
      end if;
      declare
         Digest : constant SMB.Bytes := SMB.Crypto.HMAC_SHA256 (Key, Data);
      begin
         for Index in 0 .. 15 loop
            Signature (Index) := Digest (Digest'First + Index);
         end loop;
      end;
      Status := SMB.Ok;
   end Compute_Signature;

   procedure Verify_Signature
     (Data : SMB.Bytes;
      Key : SMB.Bytes;
      Valid : out Boolean;
      Status : out SMB.Core_Status) is
   begin
      Valid := False;
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if Key'Length = 0 then
         Status := SMB.Invalid_Value;
         return;
      end if;
      declare
         Zero_Signature : constant SMB.Bytes (0 .. 15) := (others => 0);
         Given : SMB.Bytes (0 .. 15);
         Digest : SMB.Crypto.Digest_256;
         Context : SMB.Crypto.HMAC_SHA256_Context;
      begin
         for Index in 0 .. 15 loop
            Given (Index) := Data (Data'First + 48 + Index);
         end loop;
         SMB.Crypto.HMAC_SHA256_Start (Context, Key);
         SMB.Crypto.HMAC_SHA256_Update
           (Context, Data (Data'First .. Data'First + 47));
         SMB.Crypto.HMAC_SHA256_Update (Context, Zero_Signature);
         if Data'Length > Header_Size then
            SMB.Crypto.HMAC_SHA256_Update
              (Context, Data (Data'First + Header_Size .. Data'Last));
         end if;
         SMB.Crypto.HMAC_SHA256_Finish (Context, Digest);
         Valid := SMB.Crypto.Constant_Time_Equal
           (Given, Digest (Digest'First .. Digest'First + 15));
      end;
      Status := SMB.Ok;
   end Verify_Signature;

   --  SMB2 CANCEL (MS-SMB2 2.2.1).
   Cancel_Command : constant := 16#000C#;

   function GMAC_Nonce (Data : SMB.Bytes) return SMB.AES.GCM.Nonce_96 is
     (Data (Data'First + 24), Data (Data'First + 25), Data (Data'First + 26),
      Data (Data'First + 27), Data (Data'First + 28), Data (Data'First + 29),
      Data (Data'First + 30), Data (Data'First + 31),
      (Data (Data'First + 16) and 1)
        or (if Encoded_U16 (Data, 12) = Cancel_Command then 2 else 0),
      0, 0, 0);

   procedure Sign_SMB3
     (Data : in out SMB.Bytes;
      Key : SMB.AES.Key_128;
      Algorithm : SMB.Core_Negotiate.SMB3_Signing_Id;
      Status : out SMB.Core_Status) is
   begin
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      for Index in 48 .. 63 loop
         Data (Data'First + Index) := 0;
      end loop;
      declare
         Signature : Signature_Bytes;
      begin
         Compute_Signature_SMB3 (Data, Key, Algorithm, Signature, Status);
         Data (Data'First + 48 .. Data'First + 63) := Signature;
      end;
   end Sign_SMB3;

   procedure Compute_Signature_SMB3
     (Data : SMB.Bytes;
      Key : SMB.AES.Key_128;
      Algorithm : SMB.Core_Negotiate.SMB3_Signing_Id;
      Signature : out Signature_Bytes;
      Status : out SMB.Core_Status) is
   begin
      Signature := (others => 0);
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      declare
         Tag : constant SMB.AES.CMAC.Tag_128 :=
           (case Algorithm is
              when SMB.Core_Negotiate.AES_CMAC =>
                 SMB.AES.CMAC.MAC (Key, Data),
              when SMB.Core_Negotiate.AES_GMAC =>
                 SMB.AES.GCM.MAC (Key, GMAC_Nonce (Data), Data));
      begin
         for Index in 0 .. 15 loop
            Signature (Index) := Tag (Index);
         end loop;
      end;
      Status := SMB.Ok;
   end Compute_Signature_SMB3;

   procedure Verify_Signature_SMB3
     (Data : SMB.Bytes;
      Key : SMB.AES.Key_128;
      Algorithm : SMB.Core_Negotiate.SMB3_Signing_Id;
      Valid : out Boolean;
      Status : out SMB.Core_Status) is
   begin
      Valid := False;
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      declare
         Zero_Signature : constant SMB.Bytes (0 .. 15) := (others => 0);
         Given : constant SMB.Bytes (0 .. 15) :=
           Data (Data'First + 48 .. Data'First + 63);
         Tag : SMB.Bytes (0 .. 15);
      begin
         --  The header up to the Signature field, a zero signature and the
         --  rest. For a bare header that ends at Natural'Last, the rest's
         --  first index would overflow, so it is skipped when empty. The
         --  first two pieces are whole blocks, as GMAC's Update needs.
         case Algorithm is
            when SMB.Core_Negotiate.AES_CMAC =>
               declare
                  Context : SMB.AES.CMAC.MAC_Context;
               begin
                  SMB.AES.CMAC.Start (Context, Key);
                  SMB.AES.CMAC.Update
                    (Context, Data (Data'First .. Data'First + 47));
                  SMB.AES.CMAC.Update (Context, Zero_Signature);
                  if Data'Length > Header_Size then
                     SMB.AES.CMAC.Update
                       (Context, Data (Data'First + Header_Size .. Data'Last));
                  end if;
                  SMB.AES.CMAC.Finish (Context, Tag);
               end;
            when SMB.Core_Negotiate.AES_GMAC =>
               declare
                  Context : SMB.AES.GCM.MAC_Context;
               begin
                  SMB.AES.GCM.Start (Context, Key, GMAC_Nonce (Data));
                  SMB.AES.GCM.Update
                    (Context, Data (Data'First .. Data'First + 47));
                  SMB.AES.GCM.Update (Context, Zero_Signature);
                  if Data'Length > Header_Size then
                     SMB.AES.GCM.Update
                       (Context, Data (Data'First + Header_Size .. Data'Last));
                  end if;
                  SMB.AES.GCM.Finish (Context, Tag);
               end;
         end case;
         Valid := SMB.Crypto.Constant_Time_Equal (Given, Tag);
      end;
      Status := SMB.Ok;
   end Verify_Signature_SMB3;
end SMB.Core_Wire;
