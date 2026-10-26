with SMB.Core_Text;

package body SMB.Core_Protocol with SPARK_Mode is
   use type SMB.Byte;
   use type SMB.DWord;
   use type SMB.QWord;
   use type SMB.Word;
   use type SMB.Core_Wire.Command_Code;

   Negotiate_Command : constant SMB.Core_Wire.Command_Code := 0;
   Session_Setup_Command : constant SMB.Core_Wire.Command_Code := 1;
   Logoff_Command : constant SMB.Core_Wire.Command_Code := 2;
   Tree_Connect_Command : constant SMB.Core_Wire.Command_Code := 3;
   Tree_Disconnect_Command : constant SMB.Core_Wire.Command_Code := 4;
   Create_Command : constant SMB.Core_Wire.Command_Code := 5;
   Close_Command : constant SMB.Core_Wire.Command_Code := 6;
   Read_Command : constant SMB.Core_Wire.Command_Code := 8;
   Write_Command : constant SMB.Core_Wire.Command_Code := 9;
   Query_Directory_Command : constant SMB.Core_Wire.Command_Code := 14;
   Set_Info_Command : constant SMB.Core_Wire.Command_Code := 17;

   procedure Clear (Output : out SMB.Bytes) is
   begin
      for I in Output'Range loop
         Output (I) := 0;
      end loop;
   end Clear;

   procedure Copy
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.Bytes;
      Status : out SMB.Core_Status)
   with Pre =>
     Output'Length <= SMB.Maximum_Frame_Size
     and then Value'Length <= SMB.Maximum_Frame_Size;

   procedure Copy
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.Bytes;
      Status : out SMB.Core_Status) is
   begin
      if Position > Output'Length
        or else Value'Length > Output'Length - Position
      then
         Status := SMB.Resource_Limit;
         return;
      end if;
      if Value'Length > 0 then
         Output (Output'First + Position
                   .. Output'Last - (Output'Length - Position - Value'Length))
           := Value;
      end if;
      Status := SMB.Ok;
   end Copy;

   procedure Put_U16
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.Word;
      Status : in out SMB.Core_Status) is
   begin
      if Status = SMB.Ok then
         SMB.Core_Wire.Write_U16 (Output, Position, Value, Status);
      end if;
   end Put_U16;

   procedure Put_U32
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.DWord;
      Status : in out SMB.Core_Status) is
   begin
      if Status = SMB.Ok then
         SMB.Core_Wire.Write_U32 (Output, Position, Value, Status);
      end if;
   end Put_U32;

   procedure Put_U64
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.QWord;
      Status : in out SMB.Core_Status) is
   begin
      if Status = SMB.Ok then
         SMB.Core_Wire.Write_U64 (Output, Position, Value, Status);
      end if;
   end Put_U64;

   procedure Begin_Build
     (Output : out SMB.Bytes;
      Required : Natural;
      Status : out SMB.Core_Status) is
   begin
      Status := SMB.Ok;
      Clear (Output);
      if Required > Output'Length then
         Status := SMB.Resource_Limit;
      end if;
   end Begin_Build;

   procedure Finish
     (Required : Natural;
      Used : out Natural;
      Status : SMB.Core_Status) is
   begin
      if Status = SMB.Ok then
         Used := Required;
      else
         Used := 0;
      end if;
   end Finish;

   procedure Build_Negotiate
     (Guid : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Begin_Build (Output, 38, Status);
      Put_U16 (Output, 0, 36, Status);
      Put_U16 (Output, 2, 1, Status);
      Put_U16 (Output, 4, 3, Status);
      Put_U32 (Output, 8, 0, Status);
      if Status = SMB.Ok then
         Copy (Output, 12, Guid, Status);
      end if;
      Put_U64 (Output, 28, 0, Status);
      Put_U16 (Output, 36, SMB.SMB2_Dialect_0210, Status);
      Finish (38, Used, Status);
   end Build_Negotiate;

   procedure Build_Session_Setup
     (Token : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Required : constant Natural := 24 + Token'Length;
   begin
      Begin_Build (Output, Required, Status);
      Put_U16 (Output, 0, 25, Status);
      if Status = SMB.Ok then
         Output (Output'First + 2) := 0;
         Output (Output'First + 3) := 3;
      end if;
      Put_U16 (Output, 12, 88, Status);
      if Token'Length > SMB.Word'Last then
         Status := SMB.Resource_Limit;
      else
         Put_U16 (Output, 14, SMB.Word (Token'Length), Status);
         if Status = SMB.Ok then
            Copy (Output, 24, Token, Status);
         end if;
      end if;
      Finish (Required, Used, Status);
   end Build_Session_Setup;

   procedure Build_Tree_Connect
     (Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Required : constant Natural := 8 + Name'Length;
   begin
      Begin_Build (Output, Required, Status);
      Put_U16 (Output, 0, 9, Status);
      Put_U16 (Output, 4, 72, Status);
      if Name'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
      elsif Name'Length > SMB.Word'Last then
         Status := SMB.Resource_Limit;
      else
         Put_U16 (Output, 6, SMB.Word (Name'Length), Status);
         if Status = SMB.Ok then
            Copy (Output, 8, Name, Status);
         end if;
      end if;
      Finish (Required, Used, Status);
   end Build_Tree_Connect;

   procedure Build_Create
     (Name : SMB.Bytes;
      Access_Mask, Disposition : SMB.DWord;
      Directory : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Name_Bytes : constant Natural := Natural'Max (1, Name'Length);
      Required : constant Natural := 56 + Name_Bytes;
   begin
      Begin_Build (Output, Required, Status);
      Put_U16 (Output, 0, 57, Status);
      Put_U32 (Output, 4, 2, Status);
      Put_U32 (Output, 24, Access_Mask, Status);
      Put_U32 (Output, 28, (if Directory then 16#10# else 0), Status);
      Put_U32 (Output, 32, 7, Status);
      Put_U32 (Output, 36, Disposition, Status);
      Put_U32 (Output, 40, (if Directory then 1 else 16#40#), Status);
      Put_U16 (Output, 44, 120, Status);
      if Name'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
      elsif Name'Length > SMB.Word'Last then
         Status := SMB.Resource_Limit;
      else
         Put_U16 (Output, 46, SMB.Word (Name'Length), Status);
         if Status = SMB.Ok and then Name'Length > 0 then
            Copy (Output, 56, Name, Status);
         end if;
      end if;
      Finish (Required, Used, Status);
   end Build_Create;

   procedure Build_Read
     (File_Id : SMB.Bytes;
      Offset : SMB.QWord;
      Amount : Natural;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Begin_Build (Output, 49, Status);
      Put_U16 (Output, 0, 49, Status);
      Put_U32 (Output, 4, SMB.DWord (Amount), Status);
      Put_U64 (Output, 8, Offset, Status);
      if Status = SMB.Ok then
         Copy (Output, 16, File_Id, Status);
      end if;
      Put_U32 (Output, 32, 0, Status);
      if Status = SMB.Ok then
         Output (Output'First + 48) := 1;
      end if;
      Finish (49, Used, Status);
   end Build_Read;

   procedure Build_Write
     (File_Id : SMB.Bytes;
      Offset : SMB.QWord;
      Data : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Required : constant Natural := 48 + Data'Length;
   begin
      Begin_Build (Output, Required, Status);
      Put_U16 (Output, 0, 49, Status);
      Put_U16 (Output, 2, 112, Status);
      Put_U32 (Output, 4, SMB.DWord (Data'Length), Status);
      Put_U64 (Output, 8, Offset, Status);
      if Status = SMB.Ok then
         Copy (Output, 16, File_Id, Status);
      end if;
      Put_U32 (Output, 44, 0, Status);
      if Status = SMB.Ok then
         Copy (Output, 48, Data, Status);
      end if;
      Finish (Required, Used, Status);
   end Build_Write;

   procedure Build_Close
     (File_Id : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Begin_Build (Output, 24, Status);
      Put_U16 (Output, 0, 24, Status);
      if Status = SMB.Ok then
         Copy (Output, 8, File_Id, Status);
      end if;
      Finish (24, Used, Status);
   end Build_Close;

   procedure Build_Query_Directory
     (File_Id : SMB.Bytes;
      Restart : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Required : constant Natural := 34;
   begin
      Begin_Build (Output, Required, Status);
      Put_U16 (Output, 0, 33, Status);
      if Status = SMB.Ok then
         Output (Output'First + 2) := 37;
         Output (Output'First + 3) := (if Restart then 1 else 0);
      end if;
      if Status = SMB.Ok then
         Copy (Output, 8, File_Id, Status);
      end if;
      Put_U16 (Output, 24, 96, Status);
      Put_U16 (Output, 26, 2, Status);
      Put_U32 (Output, 28, Maximum_IO_Chunk, Status);
      if Status = SMB.Ok then
         Output (Output'First + 32) := 16#2A#;
         Output (Output'First + 33) := 0;
      end if;
      Finish (Required, Used, Status);
   end Build_Query_Directory;

   procedure Build_Disposition
     (File_Id : SMB.Bytes;
      Delete_File : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Begin_Build (Output, 33, Status);
      Put_U16 (Output, 0, 33, Status);
      if Status = SMB.Ok then
         Output (Output'First + 2) := 1;
         Output (Output'First + 3) := 13;
      end if;
      Put_U32 (Output, 4, 1, Status);
      Put_U16 (Output, 8, 96, Status);
      if Status = SMB.Ok then
         Copy (Output, 16, File_Id, Status);
         Output (Output'First + 32) := (if Delete_File then 1 else 0);
      end if;
      Finish (33, Used, Status);
   end Build_Disposition;

   procedure Build_Rename
     (File_Id : SMB.Bytes;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      Required : constant Natural := 52 + Name'Length;
   begin
      Begin_Build (Output, Required, Status);
      Put_U16 (Output, 0, 33, Status);
      if Status = SMB.Ok then
         Output (Output'First + 2) := 1;
         Output (Output'First + 3) := 10;
      end if;
      if Name'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
      elsif Name'Length > SMB.DWord'Last - 20 then
         Status := SMB.Resource_Limit;
      else
         Put_U32 (Output, 4, 20 + SMB.DWord (Name'Length), Status);
      end if;
      Put_U16 (Output, 8, 96, Status);
      if Status = SMB.Ok then
         Copy (Output, 16, File_Id, Status);
      end if;
      Put_U32 (Output, 48, SMB.DWord (Name'Length), Status);
      if Status = SMB.Ok then
         Copy (Output, 52, Name, Status);
      end if;
      Finish (Required, Used, Status);
   end Build_Rename;

   procedure Build_Simple
     (Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Begin_Build (Output, 4, Status);
      Put_U16 (Output, 0, 4, Status);
      Finish (4, Used, Status);
   end Build_Simple;

   function Fits
     (Value : SMB.DWord; Available : Natural) return Boolean is
     (SMB.QWord (Value) <= SMB.QWord (Available));

   procedure Read_U16
     (Packet : SMB.Bytes; Offset : Natural; Value : out SMB.Word;
      Status : in out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size
   is
   begin
      Value := 0;
      if Status = SMB.Ok then
         SMB.Core_Wire.Read_U16 (Packet, Offset, Value, Status);
      end if;
   end Read_U16;

   procedure Read_U32
     (Packet : SMB.Bytes; Offset : Natural; Value : out SMB.DWord;
      Status : in out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size
   is
   begin
      Value := 0;
      if Status = SMB.Ok then
         SMB.Core_Wire.Read_U32 (Packet, Offset, Value, Status);
      end if;
   end Read_U32;

   procedure Read_U64
     (Packet : SMB.Bytes; Offset : Natural; Value : out SMB.QWord;
      Status : in out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size
   is
   begin
      Value := 0;
      if Status = SMB.Ok then
         SMB.Core_Wire.Read_U64 (Packet, Offset, Value, Status);
      end if;
   end Read_U64;

   procedure Parse_Error
      (Packet : SMB.Bytes;
      Info : out Response_Info;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
        Post =>
     (if Status = SMB.Ok then
        Info.Data_Offset <= Packet'Length
        and then Info.Data_Length <= Packet'Length - Info.Data_Offset);

   procedure Parse_Error
     (Packet : SMB.Bytes;
      Info : out Response_Info;
      Status : out SMB.Core_Status) is
      Count : SMB.Word := 0;
      Byte_Count : SMB.DWord := 0;
      Available : Natural := 0;
   begin
      Info := (others => <>);
      Status := SMB.Ok;
      if Packet'Length < 72 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Available := Packet'Length - 72;
      if Packet (Packet'First + 66) /= 0
        or else Packet (Packet'First + 67) /= 0
      then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Read_U16 (Packet, 64, Count, Status);
      if Count /= 9 then
         Status := SMB.Invalid_Protocol;
         return;
      end if;
      Read_U32 (Packet, 68, Byte_Count, Status);
      if Status /= SMB.Ok
        or else not Fits (Byte_Count, Available)
      then
         Status := SMB.Invalid_Offset;
      end if;
   end Parse_Error;

   procedure Parse_Response
     (Packet : SMB.Bytes;
      Command : SMB.Core_Wire.Command_Code;
      Nt_Status : SMB.DWord;
      Info : out Response_Info;
      Status : out SMB.Core_Status) is
      Structure : SMB.Word := 0;
      Word_Value : SMB.Word := 0;
      DWord_Value : SMB.DWord := 0;
      Offset : Natural;
      Length : Natural;
      Header_Status : SMB.Core_Status := SMB.Ok;
   begin
      Info := (others => <>);
      Status := SMB.Ok;
      case Command is
         when Negotiate_Command | Session_Setup_Command | Logoff_Command
            | Tree_Connect_Command | Tree_Disconnect_Command
            | Create_Command | Close_Command | Read_Command | Write_Command
            | Query_Directory_Command | Set_Info_Command =>
            null;
         when others =>
            Status := SMB.Unsupported_Feature;
            return;
      end case;
      if Nt_Status /= SMB.Success
        and then not (Command = Session_Setup_Command
                      and then Nt_Status = SMB.Status_More_Processing_Required)
      then
         Parse_Error (Packet, Info, Status);
         return;
      end if;
      if Packet'Length < 64 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if Command = Negotiate_Command then
         if Packet'Length < 128 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Read_U16 (Packet, 66, Word_Value, Header_Status);
         if Structure /= 65
           or else (Word_Value and 1) = 0
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Read_U16 (Packet, 68, Word_Value, Header_Status);
         Read_U16 (Packet, 70, Structure, Header_Status);
         if Word_Value /= SMB.SMB2_Dialect_0210 or else Structure /= 0 then
            Status := SMB.Unsupported_Feature;
            return;
         end if;
         Read_U64 (Packet, 40, Info.Session_Id, Header_Status);
         Read_U32 (Packet, 36, Info.Tree_Id, Header_Status);
         Read_U32 (Packet, 88, DWord_Value, Header_Status);
         if Info.Session_Id /= 0 or else Info.Tree_Id /= 0
           or else (DWord_Value and 16#78#) /= 0
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Read_U32 (Packet, 124, DWord_Value, Header_Status);
         if DWord_Value /= 0 then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Read_U32 (Packet, 96, DWord_Value, Header_Status);
         if DWord_Value = 0 then
            Status := SMB.Invalid_Value;
            return;
         end if;
         Info.Max_Read := Natural'Min (Maximum_IO_Chunk,
           (if SMB.QWord (DWord_Value) > SMB.QWord (Natural'Last)
            then Natural'Last else Natural (DWord_Value)));
         Read_U32 (Packet, 100, DWord_Value, Header_Status);
         if DWord_Value = 0 then
            Status := SMB.Invalid_Value;
            return;
         end if;
         Info.Max_Write := Natural'Min (Maximum_IO_Chunk,
           (if SMB.QWord (DWord_Value) > SMB.QWord (Natural'Last)
            then Natural'Last else Natural (DWord_Value)));
         Read_U16 (Packet, 120, Word_Value, Header_Status);
         Read_U16 (Packet, 122, Structure, Header_Status);
         if Header_Status /= SMB.Ok then
            Status := Header_Status;
            return;
         end if;
         if SMB.QWord (Word_Value) > SMB.QWord (Packet'Length)
           or else SMB.QWord (Structure) >
             SMB.QWord (Packet'Length) - SMB.QWord (Word_Value)
         then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         if Structure > 0 then
            if Word_Value < 128 then
               Status := SMB.Invalid_Offset;
               return;
            end if;
            Offset := Natural (Word_Value);
            Length := Natural (Structure);
            Info.Data_Offset := Offset;
            Info.Data_Length := Length;
         end if;
      elsif Command = Session_Setup_Command then
         if Packet'Length < 72 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Read_U16 (Packet, 66, Word_Value, Header_Status);
         Read_U64 (Packet, 40, Info.Session_Id, Header_Status);
         if Structure /= 9 or else Word_Value /= 0
           or else Info.Session_Id = 0
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Read_U16 (Packet, 68, Word_Value, Header_Status);
         Read_U16 (Packet, 70, Structure, Header_Status);
         if Header_Status /= SMB.Ok then
            Status := Header_Status;
            return;
         end if;
         Offset := Natural (Word_Value);
         Length := Natural (Structure);
         if Length > 0 and then Offset < 72 then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         if Offset > Packet'Length
           or else Length > Packet'Length - Offset
         then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         Info.Data_Offset := Offset;
         Info.Data_Length := Length;
      elsif Command = Tree_Connect_Command then
         if Packet'Length < 80 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Read_U32 (Packet, 36, Info.Tree_Id, Header_Status);
         if Structure /= 16 or else Packet (Packet'First + 66) /= 1
           or else Packet (Packet'First + 67) /= 0
           or else Info.Tree_Id = 0
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         if (DWord_Value and 16#8000#) /= 0 then
            Status := SMB.Unsupported_Feature;
         end if;
      elsif Command = Create_Command then
         if Packet'Length < 152 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         if Structure /= 89
           or else Packet (Packet'First + 66) /= 0
           or else Packet (Packet'First + 67) /= 0
         then
            Status := SMB.Unsupported_Feature;
            return;
         end if;
         for I in 0 .. 15 loop
            Info.File_Id (I) := Packet (Packet'First + 128 + I);
         end loop;
         Read_U32 (Packet, 144, DWord_Value, Header_Status);
         if not Fits (DWord_Value, Packet'Length) then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         Offset := Natural (DWord_Value);
         if Offset > Packet'Length then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         Read_U32 (Packet, 148, DWord_Value, Header_Status);
         if not Fits (DWord_Value, Packet'Length - Offset) then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         if DWord_Value /= 0 then
            Status := SMB.Unsupported_Feature;
         end if;
      elsif Command = Read_Command then
         if Packet'Length < 80 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         if Structure /= 17 or else Packet (Packet'First + 67) /= 0 then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Read_U32 (Packet, 76, DWord_Value, Header_Status);
         if DWord_Value /= 0 then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Offset := Natural (Packet (Packet'First + 66));
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         if not Fits (DWord_Value, Maximum_IO_Chunk) then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Length := Natural (DWord_Value);
         if Offset > Packet'Length
           or else Length > Packet'Length - Offset
           or else (Length > 0 and then Offset < 80)
         then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         Info.Data_Offset := Offset;
         Info.Data_Length := Length;
      elsif Command = Write_Command then
         if Packet'Length < 80 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Read_U16 (Packet, 66, Word_Value, Header_Status);
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         if Structure /= 17 or else Word_Value /= 0
           or else DWord_Value = 0
           or else not Fits (DWord_Value, Maximum_IO_Chunk)
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Info.Count := Natural (DWord_Value);
         Read_U16 (Packet, 76, Word_Value, Header_Status);
         Read_U16 (Packet, 78, Structure, Header_Status);
         if Word_Value /= 0 or else Structure /= 0 then
            Status := SMB.Unsupported_Feature;
         end if;
      elsif Command = Close_Command then
         if Packet'Length < 124 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Read_U16 (Packet, 66, Word_Value, Header_Status);
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         if Structure /= 60 or else (Word_Value and 16#FFFE#) /= 0
           or else DWord_Value /= 0
         then
            Status := SMB.Invalid_Protocol;
         end if;
      elsif Command = Query_Directory_Command then
         if Packet'Length < 72 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Read_U16 (Packet, 66, Word_Value, Header_Status);
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         if Structure /= 9
           or else not Fits (DWord_Value, Maximum_IO_Chunk)
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Offset := Natural (Word_Value);
         Length := Natural (DWord_Value);
         if Offset > Packet'Length
           or else Length > Packet'Length - Offset
           or else (Length > 0 and then Offset < 72)
         then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         Info.Data_Offset := Offset;
         Info.Data_Length := Length;
      elsif Command = Set_Info_Command then
         if Packet'Length < 66 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         if Structure /= 2 then
            Status := SMB.Invalid_Protocol;
         end if;
      elsif Command = Tree_Disconnect_Command
        or else Command = Logoff_Command
      then
         if Packet'Length < 68 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Read_U16 (Packet, 66, Word_Value, Header_Status);
         if Structure /= 4 or else Word_Value /= 0 then
            Status := SMB.Invalid_Protocol;
         end if;
      else
         Status := SMB.Unsupported_Feature;
      end if;
      if Header_Status /= SMB.Ok and then Status = SMB.Ok then
         Status := Header_Status;
      end if;
      if Status = SMB.Ok
        and then
          (Info.Data_Offset > Packet'Length
           or else Info.Data_Length > Packet'Length - Info.Data_Offset)
      then
         Status := SMB.Invalid_Offset;
      end if;
   end Parse_Response;

   procedure Parse_Directory_Entry
     (Buffer : SMB.Bytes;
      Cursor : in out Natural;
      Info : out Directory_Info;
      Status : out SMB.Core_Status) is
      Next_Offset : SMB.DWord;
      Name_Length : SMB.DWord;
      Entry_Length : Natural;
      Remaining : Natural;
      Short_Name_Length : SMB.Byte;
      Name_Offset_Value : Natural;
      Name_Length_Value : Natural;
      Text_Status : SMB.Core_Status;
      Wire_Status : SMB.Core_Status := SMB.Ok;
   begin
      Info := (others => <>);
      Status := SMB.Ok;
      if Cursor >= Buffer'Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Remaining := Buffer'Length - Cursor;
      if Remaining < 104 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Read_U32 (Buffer, Cursor, Next_Offset, Wire_Status);
      Read_U64 (Buffer, Cursor + 40, Info.Size, Wire_Status);
      Read_U32 (Buffer, Cursor + 56, Info.Attributes, Wire_Status);
      Read_U32 (Buffer, Cursor + 60, Name_Length, Wire_Status);
      Short_Name_Length := Buffer (Buffer'First + Cursor + 68);
      if Wire_Status /= SMB.Ok
        or else not Fits (Name_Length, Remaining - 104)
        or else not Fits (Name_Length, Maximum_Name_Bytes)
        or else Name_Length = 0
        or else Short_Name_Length > 24
        or else Short_Name_Length mod 2 /= 0
      then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      if Name_Length mod 2 /= 0 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      if Next_Offset = 0 then
         Entry_Length := Remaining;
         Info.Next_Cursor := Buffer'Length;
      elsif not Fits (Next_Offset, Remaining)
        or else Next_Offset < 104
        or else Next_Offset mod 8 /= 0
      then
         Status := SMB.Invalid_Offset;
         return;
      else
         Entry_Length := Natural (Next_Offset);
         Info.Next_Cursor := Cursor + Entry_Length;
      end if;
      if Entry_Length > Remaining
        or else Natural (Name_Length) > Entry_Length - 104
      then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Name_Offset_Value := Cursor + 104;
      Name_Length_Value := Natural (Name_Length);
      if Name_Offset_Value > Buffer'Length
        or else Name_Length_Value > Buffer'Length - Name_Offset_Value
      then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      if Name_Length_Value mod 2 /= 0 then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      SMB.Core_Text.Validate_UTF16
        (Buffer (Buffer'First + Name_Offset_Value
           .. Buffer'Last
             - (Buffer'Length - Name_Offset_Value - Name_Length_Value)),
         Text_Status);
      if Text_Status /= SMB.Ok then
         Status := Text_Status;
         return;
      end if;
      Info.Name_Offset := Name_Offset_Value;
      Info.Name_Length := Name_Length_Value;
      if Info.Next_Cursor <= Cursor or else Info.Next_Cursor > Buffer'Length then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Cursor := Info.Next_Cursor;
   end Parse_Directory_Entry;

   procedure Advance_Transfer
     (Position : in out SMB.QWord;
      Remaining : in out Natural;
      Requested, Count : Natural;
      Status : out SMB.Core_Status;
      Require_Progress : Boolean := True) is
   begin
      Status := SMB.Ok;
      if Count = 0 and then Requested /= 0 and then Require_Progress then
         Status := SMB.Invalid_Value;
         return;
      end if;
      if Count > Requested or else Count > Remaining then
         Status := SMB.Invalid_Value;
         return;
      end if;
      if SMB.QWord (Count) > SMB.QWord'Last - Position then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Position := Position + SMB.QWord (Count);
      Remaining := Remaining - Count;
   end Advance_Transfer;

   procedure Select_Transfer_Amount
     (Remaining, Limit : Natural;
      Amount : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Amount := 0;
      if Remaining = 0 then
         Status := SMB.Ok;
      elsif Limit = 0 then
         Status := SMB.Invalid_Value;
      else
         Amount := Natural'Min (Remaining, Limit);
         Status := SMB.Ok;
      end if;
   end Select_Transfer_Amount;

   procedure Check_Transfer_Range
     (Base_Offset : SMB.QWord;
      Total : Natural;
      Status : out SMB.Core_Status) is
   begin
      if SMB.QWord (Total) > SMB.QWord'Last - Base_Offset then
         Status := SMB.Invalid_Offset;
      else
         Status := SMB.Ok;
      end if;
   end Check_Transfer_Range;

   procedure Count_Directory_Page
     (Pages : in out Natural;
      Status : out SMB.Core_Status) is
   begin
      if Pages >= Maximum_Directory_Pages then
         Status := SMB.Resource_Limit;
      else
         Pages := Pages + 1;
         Status := SMB.Ok;
      end if;
   end Count_Directory_Page;

   procedure Count_Directory_Entry
     (Entries : in out Natural;
      Status : out SMB.Core_Status) is
   begin
      if Entries >= Maximum_Directory_Entries then
         Status := SMB.Resource_Limit;
      else
         Entries := Entries + 1;
         Status := SMB.Ok;
      end if;
   end Count_Directory_Entry;
end SMB.Core_Protocol;
