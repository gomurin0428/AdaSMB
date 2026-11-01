with Interfaces;
with SMB.Core_NTLM;
with SMB.Core_Text;
with SMB.Core_Wire;

package body SMB.Core_Auth is
   pragma SPARK_Mode (On);

   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;

   NTLM_Flags : constant SMB.DWord := 16#2088_8215#;
   Required_Flags : constant SMB.DWord := 16#0088_8211#;
   Type1_Length : constant := 32;
   Type3_Header_Length : constant := 88;

   procedure Validate_Credentials
     (User, Password, Domain : String;
      Status : out SMB.Core_Status)
   is
      Upper_User : String (1 .. Maximum_Credential_Bytes) :=
        (others => Character'Val (0));
      Encoded : SMB.Bytes (1 .. 2 * Maximum_Credential_Bytes);
      Used : Natural;
   begin
      if not Storage_Bounded (User, Maximum_Credential_Bytes)
        or else not Storage_Bounded (Password, Maximum_Credential_Bytes)
        or else not Storage_Bounded (Domain, Maximum_Credential_Bytes)
      then
         Status := SMB.Resource_Limit;
         return;
      end if;
      if User'Length = 0 then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.Uppercase_NTLM_User
        (User, Upper_User (1 .. User'Length), Status);
      if Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.UTF8_To_UTF16 (Password, Encoded, Used, Status);
      if Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.UTF8_To_UTF16
        (Upper_User (1 .. User'Length), Encoded, Used, Status);
      if Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.UTF8_To_UTF16 (Domain, Encoded, Used, Status);
      if Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
      end if;
   end Validate_Credentials;

   procedure Read_U16
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.Word;
      Status : out SMB.Core_Status)
   with Pre => Storage_Bounded (Data, Maximum_Security_Token);

   procedure Read_U16
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.Word;
      Status : out SMB.Core_Status) is
   begin
      SMB.Core_Wire.Read_U16 (Data, Offset, Value, Status);
   end Read_U16;

   procedure Read_U32
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.DWord;
      Status : out SMB.Core_Status)
   with Pre => Storage_Bounded (Data, Maximum_Security_Token);

   procedure Read_U32
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.DWord;
      Status : out SMB.Core_Status) is
   begin
      SMB.Core_Wire.Read_U32 (Data, Offset, Value, Status);
   end Read_U32;

   procedure Read_U64
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.QWord;
      Status : out SMB.Core_Status)
   with Pre => Storage_Bounded (Data, Maximum_Security_Token);

   procedure Read_U64
     (Data : SMB.Bytes; Offset : Natural; Value : out SMB.QWord;
      Status : out SMB.Core_Status) is
   begin
      SMB.Core_Wire.Read_U64 (Data, Offset, Value, Status);
   end Read_U64;

   procedure Append_Byte
     (Data : in out SMB.Bytes; Used : in out Natural; Value : SMB.Byte;
      Status : out SMB.Core_Status)
   with Pre =>
     Storage_Bounded (Data, Maximum_Security_Token)
     and then Used <= Data'Length,
     Post => Used <= Data'Length
       and then (if Status = SMB.Ok then Used = Used'Old + 1);

   procedure Append_Byte
     (Data : in out SMB.Bytes; Used : in out Natural; Value : SMB.Byte;
      Status : out SMB.Core_Status) is
   begin
      if Used >= Data'Length then
         Status := SMB.Resource_Limit;
      else
         Data (Data'First + Used) := Value;
         Used := Used + 1;
         Status := SMB.Ok;
      end if;
   end Append_Byte;

   procedure Append_Data
     (Data : in out SMB.Bytes; Used : in out Natural; Value : SMB.Bytes;
      Status : out SMB.Core_Status)
   with Pre =>
     Storage_Bounded
       (Data, 2 * Maximum_Security_Token + Type1_Length)
     and then Used <= Data'Length
     and then Storage_Bounded (Value, Maximum_Security_Token),
     Post => Used <= Data'Length
       and then (if Status = SMB.Ok then Used = Used'Old + Value'Length);

   procedure Append_Data
     (Data : in out SMB.Bytes; Used : in out Natural; Value : SMB.Bytes;
      Status : out SMB.Core_Status) is
   begin
      if Used > Data'Length or else Value'Length > Data'Length - Used then
         Status := SMB.Resource_Limit;
         return;
      end if;
      if Value'Length > 0 then
         Data (Data'First + Used
               .. Data'First + (Used + Value'Length - 1)) := Value;
      end if;
      Used := Used + Value'Length;
      Status := SMB.Ok;
   end Append_Data;

   procedure Append_Length
     (Data : in out SMB.Bytes; Used : in out Natural; Value : Natural;
      Status : out SMB.Core_Status)
   with Pre =>
     Storage_Bounded (Data, Maximum_Security_Token)
     and then Used <= Data'Length,
     Post => Used <= Data'Length;

   procedure Append_Length
     (Data : in out SMB.Bytes; Used : in out Natural; Value : Natural;
      Status : out SMB.Core_Status) is
   begin
      if Value < 128 then
         Append_Byte (Data, Used, SMB.Byte (Value), Status);
      elsif Value <= 16#FF# then
         Append_Byte (Data, Used, 16#81#, Status);
         if Status = SMB.Ok then
            Append_Byte (Data, Used, SMB.Byte (Value), Status);
         end if;
      elsif Value <= 16#FFFF# then
         Append_Byte (Data, Used, 16#82#, Status);
         if Status = SMB.Ok then
            Append_Byte (Data, Used, SMB.Byte (Value / 256), Status);
         end if;
         if Status = SMB.Ok then
            Append_Byte (Data, Used, SMB.Byte (Value mod 256), Status);
         end if;
      else
         Status := SMB.Resource_Limit;
      end if;
   end Append_Length;

   procedure Append_TLV
     (Data : in out SMB.Bytes; Used : in out Natural;
      Tag : SMB.Byte; Value : SMB.Bytes; Status : out SMB.Core_Status)
   with Pre =>
     Storage_Bounded (Data, Maximum_Security_Token)
     and then Used <= Data'Length
     and then Storage_Bounded (Value, Maximum_Security_Token),
     Post => Used <= Data'Length;

   procedure Append_TLV
     (Data : in out SMB.Bytes; Used : in out Natural;
      Tag : SMB.Byte; Value : SMB.Bytes; Status : out SMB.Core_Status) is
   begin
      if Value'Length > 16#FFFF# then
         Status := SMB.Resource_Limit;
         return;
      end if;
      Append_Byte (Data, Used, Tag, Status);
      if Status = SMB.Ok then
         Append_Length (Data, Used, Value'Length, Status);
      end if;
      if Status = SMB.Ok then
         Append_Data (Data, Used, Value, Status);
      end if;
   end Append_TLV;

   function DER_Header_Size (Length : Natural) return Natural is
     (if Length < 128 then 2 elsif Length <= 16#FF# then 3 else 4);

   procedure Process_Target_Info
     (Input : SMB.Bytes;
      Output : in out SMB.Bytes;
      Used : out Natural;
      Server_Time : out SMB.QWord;
      Has_Timestamp : out Boolean;
      Status : out SMB.Core_Status)
   with Pre =>
     Storage_Bounded (Input, Maximum_Security_Token)
     and then Storage_Bounded (Output, Maximum_Security_Token),
     Post => Used <= Output'Length
       and then (if Status /= SMB.Ok then Used = 0);

   procedure Build_Type3
     (User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Current_Filetime : SMB.QWord;
      Type1, Type2 : SMB.Bytes;
      Server_Flags : SMB.DWord;
      Target_Info : SMB.Bytes;
      Target_Info_Used : Natural;
      Server_Time : SMB.QWord;
      Has_Timestamp : Boolean;
      Output : in out SMB.Bytes;
      Used : out Natural;
      Session_Key : out SMB.Crypto.Digest_128;
      Status : out SMB.Core_Status)
   with Pre =>
     Storage_Bounded (User, Maximum_Credential_Bytes)
     and then Storage_Bounded (Password, Maximum_Credential_Bytes)
     and then Storage_Bounded (Domain, Maximum_Credential_Bytes)
     and then Storage_Bounded (Nonce, 8)
     and then Nonce'Length = 8
     and then Storage_Bounded (Type1, Type1_Length)
     and then Type1'Length = Type1_Length
     and then Storage_Bounded (Type2, Maximum_Security_Token)
     and then Type2'Length >= 48
     and then Storage_Bounded (Target_Info, Maximum_Security_Token)
     and then Target_Info_Used <= Target_Info'Length
     and then Storage_Bounded (Output, Maximum_Security_Token)
     and then (for all Index in Output'Range => Output (Index) = 0),
     Post => Used <= Output'Length
       and then
         (if Status /= SMB.Ok then
            Used = 0 and Session_Key = (Session_Key'Range => 0))
       and then (for all Index in Output'Range =>
          (if Index - Output'First >= Used then Output (Index) = 0));

   procedure Process_Target_Info
     (Input : SMB.Bytes;
      Output : in out SMB.Bytes;
      Used : out Natural;
      Server_Time : out SMB.QWord;
      Has_Timestamp : out Boolean;
      Status : out SMB.Core_Status)
   is
      Seen : array (1 .. 10) of Boolean := (others => False);
      Position : Natural := 0;
      Id : SMB.Word;
      Size_Word : SMB.Word;
      Value : SMB.DWord;
      Name_Status : SMB.Core_Status;
      Has_Computer : Boolean := False;
      Has_Domain : Boolean := False;
      Has_Flags : Boolean := False;
      Saw_End : Boolean := False;
      procedure Append_Word (Word_Value : SMB.Word)
      with Pre =>
        Storage_Bounded (Output, Maximum_Security_Token)
        and then Used <= Output'Length,
        Post => Used <= Output'Length;

      procedure Append_Word (Word_Value : SMB.Word) is
      begin
         Append_Byte (Output, Used, SMB.Byte (Word_Value and 16#FF#), Status);
         if Status = SMB.Ok then
            Append_Byte
              (Output, Used,
               SMB.Byte (Interfaces.Shift_Right (Word_Value, 8)), Status);
         end if;
      end Append_Word;
      procedure Append_DWord (DWord_Value : SMB.DWord)
      with Pre =>
        Storage_Bounded (Output, Maximum_Security_Token)
        and then Used <= Output'Length,
        Post => Used <= Output'Length;

      procedure Append_DWord (DWord_Value : SMB.DWord) is
      begin
         for Shift in 0 .. 3 loop
            if Status = SMB.Ok then
               Append_Byte
                 (Output, Used,
                  SMB.Byte
                    (Interfaces.Shift_Right (DWord_Value, Shift * 8)
                     and 16#FF#),
                  Status);
            end if;
         end loop;
      end Append_DWord;
      procedure Append_Source (Start, Count : Natural)
      with Pre =>
        Storage_Bounded (Input, Maximum_Security_Token)
        and then Storage_Bounded (Output, Maximum_Security_Token)
        and then Used <= Output'Length
        and then Count > 0
        and then Start <= Input'Length
        and then Count <= Input'Length - Start
        and then Start <= Natural'Last - Count,
        Post => Used <= Output'Length;

      procedure Append_Source (Start, Count : Natural) is
      begin
         Append_Data
           (Output, Used,
            Input (Input'First + Start
              .. Input'First + (Start + Count - 1)),
            Status);
      end Append_Source;
   begin
      Used := 0;
      Server_Time := 0;
      Has_Timestamp := False;
      if Input'Length < 4 then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      if Input'Length > Output'Length then
         Status := SMB.Resource_Limit;
         return;
      end if;
      while Position <= Input'Length - 4 loop
         pragma Loop_Invariant (Position <= Input'Length);
         pragma Loop_Invariant (Used <= Output'Length);
         pragma Loop_Variant (Increases => Position);
         Read_U16 (Input, Position, Id, Status);
         if Status /= SMB.Ok then
            Used := 0;
            return;
         end if;
         Read_U16 (Input, Position + 2, Size_Word, Status);
         if Status /= SMB.Ok then
            Used := 0;
            return;
         end if;
         if Natural (Size_Word) > Input'Length - Position - 4 then
            Used := 0;
            Status := SMB.Invalid_Length;
            return;
         end if;
         if Id = 0 then
            if Size_Word /= 0 or else Position + 4 /= Input'Length then
               Used := 0;
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if not Has_Computer or else not Has_Domain then
               Used := 0;
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if Used > Output'Length
              or else (if Has_Flags then 4 else 12) > Output'Length - Used
            then
               Used := 0;
               Status := SMB.Resource_Limit;
               return;
            end if;
            if not Has_Flags then
               Append_Word (6);
               if Status = SMB.Ok then Append_Word (4); end if;
               if Status = SMB.Ok then Append_DWord (2); end if;
            end if;
            if Status = SMB.Ok then
               Append_Source (Position, 4);
            end if;
            if Status /= SMB.Ok then
               Used := 0;
               return;
            end if;
            Saw_End := True;
            exit;
         end if;
         if Id <= 10 then
            if Seen (Natural (Id)) then
               Used := 0;
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Seen (Natural (Id)) := True;
         end if;
         if Id in 1 .. 5 or else Id = 9 then
            if Size_Word mod 2 /= 0
              or else ((Id = 1 or else Id = 2) and then Size_Word = 0)
            then
               Used := 0;
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if Size_Word > 0 then
               --  Valid UTF-16 excludes NUL code units.
               SMB.Core_Text.Validate_UTF16
                 (Input
                    (Input'First + Position + 4
                     .. Input'First
                       + (Position + 4 + Natural (Size_Word) - 1)),
                  Name_Status);
               if Name_Status /= SMB.Ok then
                  Used := 0;
                  Status := SMB.Invalid_Encoding;
                  return;
               end if;
            end if;
            if Id = 1 then Has_Computer := True; end if;
            if Id = 2 then Has_Domain := True; end if;
            Append_Source (Position, 4 + Natural (Size_Word));
         elsif Id = 6 then
            if Size_Word /= 4 then
               Used := 0;
               Status := SMB.Invalid_Length;
               return;
            end if;
            Read_U32 (Input, Position + 4, Value, Status);
            if Status /= SMB.Ok then Used := 0; return; end if;
            Append_Word (Id);
            if Status = SMB.Ok then Append_Word (4); end if;
            if Status = SMB.Ok then Append_DWord (Value or 2); end if;
            Has_Flags := True;
         elsif Id = 7 then
            if Size_Word /= 8 then
               Used := 0;
               Status := SMB.Invalid_Length;
               return;
            end if;
            Read_U64 (Input, Position + 4, Server_Time, Status);
            if Status /= SMB.Ok then Used := 0; return; end if;
            Has_Timestamp := True;
            Append_Source (Position, 4 + Natural (Size_Word));
         elsif Id = 10 then
            if Size_Word /= 16 then
               Used := 0;
               Status := SMB.Invalid_Length;
               return;
            end if;
            for Index in 0 .. 15 loop
               if Input (Input'First + Position + 4 + Index) /= 0 then
                  Used := 0;
                  Status := SMB.Invalid_Protocol;
                  return;
               end if;
            end loop;
            Append_Source (Position, 4 + Natural (Size_Word));
         else
            Append_Source (Position, 4 + Natural (Size_Word));
         end if;
         if Status /= SMB.Ok then
            Used := 0;
            return;
         end if;
         Position := Position + 4 + Natural (Size_Word);
      end loop;
      if not Saw_End then
         Used := 0;
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Status := SMB.Ok;
   end Process_Target_Info;

   procedure Build_Type3
     (User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Current_Filetime : SMB.QWord;
      Type1, Type2 : SMB.Bytes;
      Server_Flags : SMB.DWord;
      Target_Info : SMB.Bytes;
      Target_Info_Used : Natural;
      Server_Time : SMB.QWord;
      Has_Timestamp : Boolean;
      Output : in out SMB.Bytes;
      Used : out Natural;
      Session_Key : out SMB.Crypto.Digest_128;
      Status : out SMB.Core_Status)
   is
      Upper_User : String (1 .. Maximum_Credential_Bytes) :=
        (others => Character'Val (0));
      Upper_Status : SMB.Core_Status;
      Password_UTF16 : SMB.Bytes (0 .. 2 * Maximum_Credential_Bytes - 1);
      User_UTF16 : SMB.Bytes (0 .. 2 * Maximum_Credential_Bytes - 1);
      Domain_UTF16 : SMB.Bytes (0 .. 2 * Maximum_Credential_Bytes - 1);
      Password_Used, User_Used, Domain_Used : Natural;
      NT_Hash : SMB.Crypto.Digest_128;
      Response_Key : SMB.Crypto.Digest_128;
      Base_Key : SMB.Crypto.Digest_128;
      Timestamp : SMB.QWord := Current_Filetime;
      Blob_Length : Natural;
      Challenge : SMB.Bytes (0 .. 7);
      Challenge_Blob : SMB.Bytes (0 .. 8 + 28 + Target_Info_Used + 4 - 1) :=
        (others => 0);
      Blob : SMB.Bytes (0 .. 28 + Target_Info_Used + 4 - 1) :=
        (others => 0);
      Proof : SMB.Crypto.Digest_128;
      NT_Response : SMB.Bytes (0 .. 16 + Blob'Length - 1) :=
        (others => 0);
      LM_Response : SMB.Bytes (0 .. 23) := (others => 0);
      Identity : SMB.Bytes (0 .. 2 * Maximum_Credential_Bytes * 2 - 1) :=
        (others => 0);
      Identity_Used : Natural := 0;
      Type3_Length : Natural;
      Type3_Data : SMB.Bytes (0 .. Maximum_Security_Token - 1) :=
        (others => 0);
      Data_Offset : Natural := Type3_Header_Length;
      Auth_Material : SMB.Bytes (0 .. Type1'Length + Type2'Length
        + Maximum_Security_Token - 1) := (others => 0);
      Auth_Used : Natural;
      MIC : SMB.Crypto.Digest_128;
      Client_MIC : SMB.Crypto.Digest_128;
      Local_Status : SMB.Core_Status;
      procedure Put_Buffer
        (Position : Natural; Field_Offset, Field_Length : Natural)
      with Pre => Position <= Type3_Header_Length - 8;

      procedure Put_Buffer
        (Position : Natural; Field_Offset, Field_Length : Natural) is
      begin
         if Field_Length > Natural (SMB.Word'Last)
           or else Field_Offset > Maximum_Security_Token
         then
            Local_Status := SMB.Resource_Limit;
            return;
         end if;
         SMB.Core_Wire.Write_U16
           (Type3_Data, Position, SMB.Word (Field_Length), Local_Status);
         if Local_Status = SMB.Ok then
            SMB.Core_Wire.Write_U16
              (Type3_Data, Position + 2, SMB.Word (Field_Length), Local_Status);
         end if;
         if Local_Status = SMB.Ok then
            SMB.Core_Wire.Write_U32
              (Type3_Data, Position + 4, SMB.DWord (Field_Offset), Local_Status);
         end if;
      end Put_Buffer;
      procedure Put_Field (Field_Index : Natural; Value : SMB.Bytes)
      with Pre =>
        Field_Index <= Type3_Header_Length - 8
        and then Storage_Bounded (Value, Maximum_Security_Token);

      procedure Put_Field (Field_Index : Natural; Value : SMB.Bytes) is
      begin
         if Data_Offset > Type3_Data'Length
           or else Value'Length > Type3_Data'Length - Data_Offset
         then
            Local_Status := SMB.Resource_Limit;
            return;
         end if;
         Put_Buffer (Field_Index, Data_Offset, Value'Length);
         if Local_Status = SMB.Ok and then Value'Length > 0 then
            Type3_Data
              (Data_Offset .. Data_Offset + (Value'Length - 1)) := Value;
            Data_Offset := Data_Offset + Value'Length;
         end if;
      end Put_Field;
   begin
      Used := 0;
      Session_Key := (others => 0);
      if Target_Info_Used > Target_Info'Length
        or else Target_Info_Used = 0
        or else Type2'Length < 48
        or else User'Length = 0
      then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.Uppercase_NTLM_User
        (User, Upper_User (1 .. User'Length), Upper_Status);
      if Upper_Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.UTF8_To_UTF16
        (Password, Password_UTF16, Password_Used, Upper_Status);
      if Upper_Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.UTF8_To_UTF16
        (Upper_User (1 .. User'Length), User_UTF16, User_Used, Upper_Status);
      if Upper_Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      if User_Used = 0 then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      SMB.Core_Text.UTF8_To_UTF16
        (Domain, Domain_UTF16, Domain_Used, Upper_Status);
      if Upper_Status /= SMB.Ok then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      if Password_Used = 0 then
         NT_Hash := SMB.Crypto.MD4 (SMB.Bytes'(1 .. 0 => 0));
      else
         NT_Hash := SMB.Crypto.MD4
           (Password_UTF16 (0 .. Password_Used - 1));
      end if;
      for Index in 0 .. User_Used - 1 loop
         pragma Loop_Invariant (Identity_Used = Index);
         pragma Loop_Invariant (Identity_Used < Identity'Length);
         Identity (Identity_Used) := User_UTF16 (Index);
         Identity_Used := Identity_Used + 1;
      end loop;
      if Domain_Used > 0 then
         for Index in 0 .. Domain_Used - 1 loop
            pragma Loop_Invariant
              (Identity_Used = User_Used + Index);
            pragma Loop_Invariant (Identity_Used < Identity'Length);
            Identity (Identity_Used) := Domain_UTF16 (Index);
            Identity_Used := Identity_Used + 1;
         end loop;
      end if;
      Response_Key := SMB.Crypto.HMAC_MD5
        (NT_Hash, Identity (0 .. Identity_Used - 1));

      if Has_Timestamp then
         Timestamp := Server_Time;
      end if;
      for Index in 0 .. 7 loop
         Challenge (Index) := Type2 (Type2'First + 24 + Index);
         Blob (8 + Index) :=
           SMB.Byte (Interfaces.Shift_Right (Timestamp, Index * 8) and 16#FF#);
         Blob (16 + Index) := Nonce (Nonce'First + Index);
      end loop;
      Blob (0 .. 3) := (1, 1, 0, 0);
      Blob (28 .. 27 + Target_Info_Used) :=
        Target_Info
          (Target_Info'First .. Target_Info'First + (Target_Info_Used - 1));
      Blob_Length := 28 + Target_Info_Used + 4;
      Challenge_Blob (0 .. 7) := Challenge;
      Challenge_Blob (8 .. 7 + Blob_Length) := Blob;
      Proof := SMB.Crypto.HMAC_MD5
        (Response_Key, Challenge_Blob (0 .. 7 + Blob_Length));
      NT_Response (0 .. 15) := Proof;
      NT_Response (16 .. NT_Response'Last) := Blob;
      Base_Key := SMB.Crypto.HMAC_MD5 (Response_Key, Proof);
      if not Has_Timestamp then
         declare
            LM_Material : SMB.Bytes (0 .. 15) := (others => 0);
            LM_Hash : SMB.Crypto.Digest_128;
         begin
            LM_Material (0 .. 7) := Challenge;
            LM_Material (8 .. 15) := Nonce;
            LM_Hash := SMB.Crypto.HMAC_MD5 (Response_Key, LM_Material);
            LM_Response (0 .. 15) := LM_Hash;
            LM_Response (16 .. 23) := Nonce;
         end;
      end if;

      Type3_Length := Type3_Header_Length + LM_Response'Length
        + NT_Response'Length + Domain_Used + User_Used;
      if Type3_Length > Maximum_Security_Token
        or else Type3_Length > Natural (SMB.Word'Last)
      then
         Status := SMB.Resource_Limit;
         return;
      end if;
      Type3_Data (0 .. 7) :=
        Type2 (Type2'First .. Type2'First + 7);
      SMB.Core_Wire.Write_U32 (Type3_Data, 8, 3, Local_Status);
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      Put_Field (12, LM_Response);
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      Put_Field (20, NT_Response);
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      if Domain_Used > 0 then
         Put_Field (28, Domain_UTF16 (0 .. Domain_Used - 1));
      else
         Put_Buffer (28, Data_Offset, 0);
      end if;
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      Put_Field (36, User_UTF16 (0 .. User_Used - 1));
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      Put_Buffer (44, Data_Offset, 0);
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      Put_Buffer (52, Data_Offset, 0);
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      if Data_Offset /= Type3_Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Wire.Write_U32
        (Type3_Data, 60, NTLM_Flags and Server_Flags, Local_Status);
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      Auth_Used := 0;
      Append_Data (Auth_Material, Auth_Used, Type1, Local_Status);
      if Local_Status = SMB.Ok then
         Append_Data (Auth_Material, Auth_Used, Type2, Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         Append_Data
           (Auth_Material, Auth_Used, Type3_Data (0 .. Type3_Length - 1),
            Local_Status);
      end if;
      if Local_Status /= SMB.Ok then Status := Local_Status; return; end if;
      MIC := SMB.Crypto.HMAC_MD5
        (Base_Key, Auth_Material (0 .. Auth_Used - 1));
      Type3_Data (72 .. 87) := MIC;
      Client_MIC := SMB.Core_NTLM.Mechanism_List_MIC (Base_Key, False);

      --  NegTokenResp [1] { SEQUENCE { [2] OCTET STRING Type3,
      --  [3] OCTET STRING MIC } }, written straight into Output once the
      --  total length is known to fit.
      declare
         Octet_Length : constant Natural :=
           DER_Header_Size (Type3_Length) + Type3_Length;
         Fields_Length : constant Natural :=
           DER_Header_Size (Octet_Length) + Octet_Length + 20;
         Sequence_Length : constant Natural :=
           DER_Header_Size (Fields_Length) + Fields_Length;
         Total : constant Natural :=
           DER_Header_Size (Sequence_Length) + Sequence_Length;
         Position : Natural := 0;

         procedure Put_Header (Tag : SMB.Byte; Length : Natural)
         with Pre => Length <= 16#FFFF#
             and then Position <= Output'Length
             and then Output'Length - Position >= DER_Header_Size (Length),
           Post => Position = Position'Old + DER_Header_Size (Length);

         procedure Put_Header (Tag : SMB.Byte; Length : Natural) is
         begin
            Output (Output'First + Position) := Tag;
            if Length < 128 then
               Output (Output'First + Position + 1) := SMB.Byte (Length);
            elsif Length <= 16#FF# then
               Output (Output'First + Position + 1) := 16#81#;
               Output (Output'First + Position + 2) := SMB.Byte (Length);
            else
               Output (Output'First + Position + 1) := 16#82#;
               Output (Output'First + Position + 2) :=
                 SMB.Byte (Length / 256);
               Output (Output'First + Position + 3) :=
                 SMB.Byte (Length mod 256);
            end if;
            Position := Position + DER_Header_Size (Length);
         end Put_Header;
      begin
         if Total > Output'Length then
            Status := SMB.Resource_Limit;
            return;
         end if;
         Put_Header (16#A1#, Sequence_Length);
         Put_Header (16#30#, Fields_Length);
         Put_Header (16#A2#, Octet_Length);
         Put_Header (16#04#, Type3_Length);
         Output (Output'First + Position
                 .. Output'First + (Position + Type3_Length - 1)) :=
           Type3_Data (0 .. Type3_Length - 1);
         Position := Position + Type3_Length;
         Put_Header (16#A3#, 18);
         Put_Header (16#04#, 16);
         Output (Output'First + Position .. Output'First + (Position + 15)) :=
           Client_MIC;
         Position := Position + 16;
         pragma Assert (Position = Total);
         if Total < Output'Length then
            Output (Output'First + Total .. Output'Last) := (others => 0);
         end if;
         Used := Total;
      end;
      Session_Key := Base_Key;
      Status := SMB.Ok;
   end Build_Type3;

   procedure Build_Negotiate_Token
     (Output : in out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   is
      Type1 : SMB.Bytes (0 .. Type1_Length - 1) := (others => 0);
      OID_NTLM : constant SMB.Bytes :=
        (16#2B#, 16#06#, 16#01#, 16#04#, 16#01#,
         16#82#, 16#37#, 16#02#, 16#02#, 16#0A#);
      OID_SPNEGO : constant SMB.Bytes :=
        (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#02#);
      A, B, C, D, E, F : SMB.Bytes (0 .. 255) := (others => 0);
      A_Used, B_Used, C_Used, D_Used, E_Used, F_Used : Natural := 0;
      Local_Status : SMB.Core_Status;
   begin
      Used := 0;
      Output := (others => 0);
      Type1 (0 .. 7) :=
        (16#4E#, 16#54#, 16#4C#, 16#4D#, 16#53#, 16#53#, 16#50#, 0);
      SMB.Core_Wire.Write_U32 (Type1, 8, 1, Local_Status);
      if Local_Status /= SMB.Ok then
         Status := Local_Status;
         return;
      end if;
      SMB.Core_Wire.Write_U32 (Type1, 12, NTLM_Flags, Local_Status);
      if Local_Status /= SMB.Ok then
         Status := Local_Status;
         return;
      end if;

      Append_TLV (A, A_Used, 16#06#, OID_NTLM, Local_Status);
      if Local_Status = SMB.Ok then
         Append_TLV (B, B_Used, 16#30#, A (0 .. A_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         Append_TLV (C, C_Used, 16#A0#, B (0 .. B_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         Append_TLV (D, D_Used, 16#04#, Type1, Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         Append_TLV (E, E_Used, 16#A2#, D (0 .. D_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         Append_Data (F, F_Used, C (0 .. C_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         Append_Data (F, F_Used, E (0 .. E_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         A_Used := 0;
         Append_TLV (A, A_Used, 16#30#, F (0 .. F_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         B_Used := 0;
         Append_TLV (B, B_Used, 16#A0#, A (0 .. A_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         C_Used := 0;
         Append_TLV (C, C_Used, 16#06#, OID_SPNEGO, Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         D_Used := 0;
         Append_Data (D, D_Used, C (0 .. C_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         Append_Data (D, D_Used, B (0 .. B_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok then
         E_Used := 0;
         Append_TLV (E, E_Used, 16#60#, D (0 .. D_Used - 1), Local_Status);
      end if;
      if Local_Status = SMB.Ok
        and then E_Used > 0
        and then E_Used <= Output'Length
      then
         Output (Output'First .. Output'First + (E_Used - 1)) :=
           E (0 .. E_Used - 1);
         Used := E_Used;
         Status := SMB.Ok;
      else
         Used := 0;
         Status := (if Local_Status = SMB.Ok then SMB.Resource_Limit else Local_Status);
      end if;
   end Build_Negotiate_Token;

   procedure Authenticate
     (User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Server_Token : SMB.Bytes;
      Current_Filetime : SMB.QWord;
      Output : in out SMB.Bytes;
      Used : out Natural;
      Session_Key : out SMB.Crypto.Digest_128;
      Status : out SMB.Core_Status)
   is
      Type2_Offset, Type2_Length : Natural;
      Local_Status : SMB.Core_Status;
   begin
      Used := 0;
      Session_Key := (others => 0);
      Output := (others => 0);
      if User'Length > Maximum_Credential_Bytes
        or else Password'Length > Maximum_Credential_Bytes
        or else Domain'Length > Maximum_Credential_Bytes
      then
         Status := SMB.Resource_Limit;
         return;
      end if;
      if User'Length = 0 or else Nonce'Length /= 8 then
         Status := SMB.Unsupported_Feature;
         return;
      end if;
      if Output'Length = 0 then
         Status := SMB.Resource_Limit;
         return;
      end if;
      if Server_Token'Length = 0 then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      SMB.Core_NTLM.Extract_Challenge
        (Server_Token, Type2_Offset, Type2_Length, Local_Status);
      if Local_Status /= SMB.Ok then
         Status := Local_Status;
         return;
      end if;
      if Type2_Length < 48
        or else Type2_Offset > Server_Token'Length
        or else Type2_Length > Server_Token'Length - Type2_Offset
      then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      declare
         Type2 : SMB.Bytes renames
           Server_Token
             (Server_Token'First + Type2_Offset
              .. Server_Token'First + (Type2_Offset + Type2_Length - 1));
         Type1 : SMB.Bytes (0 .. Type1_Length - 1) := (others => 0);
         Flags : SMB.DWord;
         Target_Name_Len : SMB.Word;
         Target_Name_Off : SMB.DWord;
         Target_Len : SMB.Word;
         Target_Off : SMB.DWord;
         Read_Status : SMB.Core_Status;
      begin
         Type1 (0 .. 7) :=
           (16#4E#, 16#54#, 16#4C#, 16#4D#, 16#53#, 16#53#, 16#50#, 0);
         SMB.Core_Wire.Write_U32 (Type1, 8, 1, Read_Status);
         if Read_Status /= SMB.Ok then Status := Read_Status; return; end if;
         SMB.Core_Wire.Write_U32 (Type1, 12, NTLM_Flags, Read_Status);
         if Read_Status /= SMB.Ok then Status := Read_Status; return; end if;
         Read_U32 (Type2, 20, Flags, Read_Status);
         if Read_Status /= SMB.Ok then Status := Read_Status; return; end if;
         if (Flags and Required_Flags) /= Required_Flags then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         if (Flags and 16#0200_0000#) /= 0 and then Type2'Length < 56 then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         if (Flags and 16#0000_0004#) /= 0 then
            Read_U16 (Type2, 12, Target_Name_Len, Read_Status);
            if Read_Status /= SMB.Ok then Status := Read_Status; return; end if;
            Read_U32 (Type2, 16, Target_Name_Off, Read_Status);
            if Read_Status /= SMB.Ok then Status := Read_Status; return; end if;
         else
            Target_Name_Len := 0;
            Target_Name_Off := 0;
         end if;
         Read_U16 (Type2, 40, Target_Len, Read_Status);
         if Read_Status /= SMB.Ok then Status := Read_Status; return; end if;
         Read_U32 (Type2, 44, Target_Off, Read_Status);
         if Read_Status /= SMB.Ok then Status := Read_Status; return; end if;
         if Target_Name_Off > SMB.DWord (Type2'Length)
           or else Target_Off > SMB.DWord (Type2'Length)
           or else Target_Name_Off > SMB.DWord (Natural'Last)
           or else Target_Off > SMB.DWord (Natural'Last)
         then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         declare
            Name_Offset : constant Natural := Natural (Target_Name_Off);
            Info_Offset : constant Natural := Natural (Target_Off);
            Header_Len : constant Natural :=
              (if (Flags and 16#0200_0000#) /= 0 then 56 else 48);
            Target_Info : SMB.Bytes (0 .. Maximum_Security_Token - 1) :=
              (others => 0);
            Target_Info_Used : Natural;
            Server_Time : SMB.QWord;
            Has_Timestamp : Boolean;
         begin
            if (Target_Name_Len > 0 and then Name_Offset < Header_Len)
              or else Natural (Target_Name_Len) > Type2'Length - Name_Offset
              or else (Target_Len > 0 and then Info_Offset < Header_Len)
              or else Natural (Target_Len) > Type2'Length - Info_Offset
            then
               Status := SMB.Invalid_Offset;
               return;
            end if;
            if Target_Name_Len > 0 then
               --  Valid UTF-16 excludes NUL code units, so this is the same
               --  acceptance as decoding to UTF-8 and rejecting NUL.
               if Natural (Target_Name_Len) > 65_534 then
                  Status := SMB.Invalid_Encoding;
                  return;
               end if;
               SMB.Core_Text.Validate_UTF16
                 (Type2
                    (Type2'First + Name_Offset
                     .. Type2'First
                       + (Name_Offset + Natural (Target_Name_Len) - 1)),
                  Read_Status);
               if Read_Status /= SMB.Ok then
                  Status := SMB.Invalid_Encoding;
                  return;
               end if;
            end if;
            if Target_Len = 0 then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            declare
               Info : SMB.Bytes renames
                 Type2
                   (Type2'First + Info_Offset
                    .. Type2'First
                      + (Info_Offset + Natural (Target_Len) - 1));
            begin
               Process_Target_Info
                 (Info, Target_Info, Target_Info_Used,
                  Server_Time, Has_Timestamp, Read_Status);
               if Read_Status /= SMB.Ok or else Target_Info_Used = 0 then
                  Status := Read_Status;
                  if Read_Status = SMB.Ok then
                     Status := SMB.Invalid_Encoding;
                  end if;
                  return;
               end if;
            end;
            Build_Type3
              (User, Password, Domain, Nonce, Current_Filetime,
               Type1, Type2, Flags, Target_Info (0 .. Target_Info_Used - 1),
               Target_Info_Used, Server_Time, Has_Timestamp,
               Output, Used, Session_Key, Status);
         end;
      end;
   end Authenticate;
end SMB.Core_Auth;
