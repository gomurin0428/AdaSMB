with SMB.Crypto;

package body SMB.Core_Wire with SPARK_Mode is
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
      for I in 0 .. 7 loop
         Data (Data'First + Offset + I) :=
           SMB.Byte
             (Interfaces.Shift_Right (Value, I * 8) and 16#FF#);
         pragma Loop_Invariant
           (for all Written in 0 .. I =>
              Data (Data'First + Offset + Written) =
                U64_Byte (Value, Written));
         pragma Loop_Invariant
           (for all Index in Data'Range =>
              (if Index < Data'First + Offset
                 or else Index > Data'First + Offset + I
               then Data (Index) = Data'Loop_Entry (Index)));
      end loop;
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
      Status : out SMB.Core_Status) is
      Field_Status : SMB.Core_Status;
   begin
      if Data'Length < Header_Size then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Data (Data'First .. Data'Last - (Data'Length - Header_Size)) :=
        (others => 0);
      Data (Data'First .. Data'First + 3) :=
        (16#FE#, 16#53#, 16#4D#, 16#42#);
      Write_U16 (Data, 4, Header_Size, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Write_U16 (Data, 6, 1, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Write_U16 (Data, 12, SMB.Word (Command), Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Write_U16 (Data, 14, Credit, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Write_U64 (Data, 24, Message_Id, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Write_U32 (Data, 36, Tree_Id, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Write_U64 (Data, 40, Session_Id, Field_Status);
      Status := Field_Status;
   end Initialize_Header;

   procedure Validate_Header
     (Data : SMB.Bytes;
      Expected : Expected_Header;
      Nt_Status : out SMB.DWord;
      Status : out SMB.Core_Status;
      Async_Id : SMB.QWord := 0;
      Interim : Boolean := False) is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Structure_Size : SMB.Word;
      Command : SMB.Word;
      Credit : SMB.Word;
      Flags : SMB.DWord;
      Reserved : SMB.DWord;
      Message_Id : SMB.QWord;
      Tree_Id : SMB.DWord;
      Session_Id : SMB.QWord;
      Field_Status : SMB.Core_Status;
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
      Read_U16 (Data, 4, Structure_Size, Field_Status);
      if Field_Status /= SMB.Ok or else Structure_Size /= Header_Size then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Read_U16 (Data, 12, Command, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Read_U16 (Data, 14, Credit, Field_Status);
      if Field_Status /= SMB.Ok
        or else (Async_Id = 0 and then Credit = 0)
        or else (Async_Id /= 0 and then not Interim and then Credit /= 0)
      then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Read_U32 (Data, 16, Flags, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Read_U32 (Data, 20, Reserved, Field_Status);
      if Field_Status /= SMB.Ok or else Reserved /= 0 then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Read_U64 (Data, 24, Message_Id, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Read_U32 (Data, 36, Tree_Id, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
      Read_U64 (Data, 40, Session_Id, Field_Status);
      if Field_Status /= SMB.Ok then
         Status := Field_Status;
         return;
      end if;
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
         Digest : constant SMB.Bytes := SMB.Crypto.HMAC_SHA256 (Key, Data);
      begin
         for Index in 0 .. 15 loop
            Data (Data'First + 48 + Index) :=
              Digest (Digest'First + Index);
         end loop;
      end;
      Status := SMB.Ok;
   end Sign;

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
         Copy : SMB.Bytes (Data'Range) := Data;
         Given : SMB.Bytes (0 .. 15);
         Digest : SMB.Bytes (0 .. 31);
      begin
         for Index in 0 .. 15 loop
            Given (Index) := Data (Data'First + 48 + Index);
            Copy (Copy'First + 48 + Index) := 0;
         end loop;
         Digest := SMB.Crypto.HMAC_SHA256 (Key, Copy);
         Valid := SMB.Crypto.Constant_Time_Equal
           (Given, Digest (Digest'First .. Digest'First + 15));
      end;
      Status := SMB.Ok;
   end Verify_Signature;
end SMB.Core_Wire;
