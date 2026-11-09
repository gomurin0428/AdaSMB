with SMB.Core_Wire;

package SMB.Core_Protocol is
   pragma SPARK_Mode (On);
   use type SMB.Core_Wire.Command_Code;
   use type SMB.Byte;
   use type SMB.Word;
   use type SMB.DWord;
   use type SMB.QWord;

   Maximum_IO_Chunk : constant := 65_536;
   Maximum_Name_Bytes : constant := 65_534;
   Maximum_Directory_Entries : constant := 100_000;
   Maximum_Directory_Pages : constant := 4_096;

   type Response_Info is record
      Data_Offset : Natural := 0;
      Data_Length : Natural := 0;
      Max_Read : Natural := 0;
      Max_Write : Natural := 0;
      Session_Id : SMB.QWord := 0;
      Tree_Id : SMB.DWord := 0;
      File_Id : SMB.Bytes (0 .. 15) := (others => 0);
      Count : Natural := 0;
      --  The dialect a NEGOTIATE response selected: 2.1 or 3.1.1.
      Dialect : SMB.Word := 0;
   end record;

   type Directory_Info is record
      Next_Cursor : Natural := 0;
      Name_Offset : Natural := 0;
      Name_Length : Natural := 0;
      Size : SMB.QWord := 0;
      Attributes : SMB.DWord := 0;
   end record;

   procedure Build_Negotiate
     (Guid : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Guid'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 38
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 36
            and then SMB.Core_Wire.Encoded_U16 (Output, 2) = 1
            and then SMB.Core_Wire.Encoded_U16 (Output, 4) = 3
            and then SMB.Core_Wire.Encoded_U16 (Output, 6) = 0
            and then SMB.Core_Wire.Encoded_U32 (Output, 8) = 0
            and then SMB.Core_Wire.Encoded_U64 (Output, 28) = 0
            and then SMB.Core_Wire.Encoded_U16
              (Output, 36) = SMB.SMB2_Dialect_0210
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 12 + Index) =
                   Guid (Guid'First + Index)));

   procedure Build_Session_Setup
     (Token : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Token'Length <= 65_535
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 24 + Token'Length
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 25
            and then Output (Output'First + 2) = 0
            and then Output (Output'First + 3) = 3
            and then SMB.Core_Wire.Encoded_U16 (Output, 12) = 88
            and then SMB.Core_Wire.Encoded_U16 (Output, 14) =
              SMB.Word (Token'Length)
            and then SMB.Core_Wire.Encoded_U64 (Output, 16) = 0
            and then
              (if Token'Length = 0 then True
               else
                 (for all Index in 0 .. Token'Length - 1 =>
                    Output (Output'First + 24 + Index) =
                      Token (Token'First + Index))));

   procedure Build_Tree_Connect
     (Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 8 + Name'Length
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 9
            and then SMB.Core_Wire.Encoded_U16 (Output, 2) = 0
            and then SMB.Core_Wire.Encoded_U16 (Output, 4) = 72
            and then SMB.Core_Wire.Encoded_U16 (Output, 6) =
              SMB.Word (Name'Length)
            and then
              (for all Index in 0 .. Name'Length - 1 =>
                 Output (Output'First + 8 + Index) =
                   Name (Name'First + Index)));

   procedure Build_Create
     (Name : SMB.Bytes;
      Access_Mask, Disposition : SMB.DWord;
      Directory : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 56 + Natural'Max (1, Name'Length)
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 24 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte (Access_Mask, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 28 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte
                     ((if Directory then 16#10# else 0), Byte_Index))
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 40 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte
                     ((if Directory then 1 else 16#40#), Byte_Index))
            and then
              (for all Byte_Index in 0 .. 3 =>
                 Output (Output'First + 36 + Byte_Index) =
                   SMB.Core_Wire.U32_Byte (Disposition, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 1 =>
                 Output (Output'First + 46 + Byte_Index) =
                   SMB.Core_Wire.U16_Byte
                     (SMB.Word (Name'Length), Byte_Index)));

   procedure Build_Read
     (File_Id : SMB.Bytes;
      Offset : SMB.QWord;
      Amount : Natural;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Amount <= Maximum_IO_Chunk
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 49
            and then
              Output (Output'First + 4) =
                SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 0)
            and then Output (Output'First + 5) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 1)
            and then Output (Output'First + 6) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 2)
            and then Output (Output'First + 7) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 3)
            and then
              SMB.Core_Wire.Encoded_U64 (Output, 8) = Offset
            and then
              (for all Byte_Index in 0 .. 7 =>
                 Output (Output'First + 8 + Byte_Index) =
                   SMB.Core_Wire.U64_Byte (Offset, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 15 =>
                 Output (Output'First + 16 + Byte_Index) =
                   File_Id (File_Id'First + Byte_Index)));

   procedure Build_Write
     (File_Id : SMB.Bytes;
      Offset : SMB.QWord;
      Data : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Data'Length <= Maximum_IO_Chunk
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 48 + Data'Length
            and then
              Output (Output'First + 4) =
                SMB.Core_Wire.U32_Byte
                  (SMB.DWord (Data'Length), 0)
            and then Output (Output'First + 5) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 1)
            and then Output (Output'First + 6) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 2)
            and then Output (Output'First + 7) =
              SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 3)
            and then
              SMB.Core_Wire.Encoded_U64 (Output, 8) = Offset
            and then
              (for all Byte_Index in 0 .. 7 =>
                 Output (Output'First + 8 + Byte_Index) =
                   SMB.Core_Wire.U64_Byte (Offset, Byte_Index))
            and then
              (for all Byte_Index in 0 .. 15 =>
                 Output (Output'First + 16 + Byte_Index) =
                   File_Id (File_Id'First + Byte_Index))
            and then
              (Data'Length = 0
               or else
                 (for all Byte_Index in 0 .. Data'Length - 1 =>
                    Output (Output'First + 48 + Byte_Index) =
                      Data (Data'First + Byte_Index))));

   procedure Build_Close
     (File_Id : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 24
            and then
              Output (Output'First + 8 .. Output'First + 23) = File_Id);

   procedure Build_Query_Directory
     (File_Id : SMB.Bytes;
      Restart : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 34
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 33
            and then Output (Output'First + 2) = 37
            and then Output (Output'First + 3) =
              (if Restart then 1 else 0)
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) = 0
            and then Output (Output'First + 8 .. Output'First + 23) =
              File_Id
            and then SMB.Core_Wire.Encoded_U16 (Output, 24) = 96
            and then SMB.Core_Wire.Encoded_U16 (Output, 26) = 2
            and then SMB.Core_Wire.Encoded_U32 (Output, 28) =
              SMB.DWord (Maximum_IO_Chunk)
            and then Output (Output'First + 32) = 16#2A#
            and then Output (Output'First + 33) = 0);

   procedure Build_Disposition
     (File_Id : SMB.Bytes;
      Delete_File : Boolean;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 33
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 33
            and then Output (Output'First + 2) = 1
            and then Output (Output'First + 3) = 13
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) = 1
            and then SMB.Core_Wire.Encoded_U16 (Output, 8) = 96
            and then
              (for all Index in 10 .. 15 =>
                 Output (Output'First + Index) = 0)
            and then Output (Output'First + 10 .. Output'First + 15) =
              SMB.Bytes'(10 .. 15 => 0)
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 16 + Index) =
                   File_Id (File_Id'First + Index))
            and then Output (Output'First + 32) =
              (if Delete_File then 1 else 0));

   procedure Build_Rename
     (File_Id : SMB.Bytes;
      Name : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => File_Id'Length = 16
     and then Name'Length <= Maximum_Name_Bytes
     and then Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 52 + Name'Length
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 33
            and then Output (Output'First + 2) = 1
            and then Output (Output'First + 3) = 10
            and then SMB.Core_Wire.Encoded_U32 (Output, 4) =
              SMB.DWord (20 + Name'Length)
            and then SMB.Core_Wire.Encoded_U16 (Output, 8) = 96
            and then
              (for all Index in 10 .. 15 =>
                 Output (Output'First + Index) = 0)
            and then Output (Output'First + 10 .. Output'First + 15) =
              SMB.Bytes'(10 .. 15 => 0)
            and then
              (for all Index in 0 .. 15 =>
                 Output (Output'First + 16 + Index) =
                   File_Id (File_Id'First + Index))
            and then
              (for all Index in 32 .. 47 =>
                 Output (Output'First + Index) = 0)
            and then Output (Output'First + 32 .. Output'First + 47) =
              SMB.Bytes'(32 .. 47 => 0)
            and then SMB.Core_Wire.Encoded_U32 (Output, 48) =
              SMB.DWord (Name'Length)
            and then
              (if Name'Length > 0 then
                 Output (Output'First + 52 .. Output'First + (Used - 1)) =
                   Name)
            and then
              (Name'Length = 0
               or else
                 (for all Index in 0 .. Name'Length - 1 =>
                    Output (Output'First + 52 + Index) =
                      Name (Name'First + Index))));

   procedure Build_Simple
     (Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
     Post =>
       Used <= Output'Length
       and then
         (if Status = SMB.Ok then
            Used = 4
            and then SMB.Core_Wire.Encoded_U16 (Output, 0) = 4
            and then SMB.Core_Wire.Encoded_U16 (Output, 2) = 0);

   procedure Parse_Response
     (Packet : SMB.Bytes;
      Command : SMB.Core_Wire.Command_Code;
      Nt_Status : SMB.DWord;
      Info : out Response_Info;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
     Post => (if Status = SMB.Ok then
       Info.Data_Offset <= Packet'Length
       and then Info.Data_Length <= Packet'Length - Info.Data_Offset
       and then
         (if Command = 0 and then Nt_Status = SMB.Success then
            Packet'Length >= 128
            and then Info.Max_Read in 1 .. Maximum_IO_Chunk
            and then Info.Max_Write in 1 .. Maximum_IO_Chunk
            and then Info.Max_Read = Natural (SMB.DWord'Min
              (Maximum_IO_Chunk, SMB.Core_Wire.Encoded_U32 (Packet, 96)))
            and then Info.Max_Write = Natural (SMB.DWord'Min
              (Maximum_IO_Chunk, SMB.Core_Wire.Encoded_U32 (Packet, 100)))
          elsif Command = 3 and then Nt_Status = SMB.Success then
            Packet'Length >= 80
            and then Info.Tree_Id /= 0
            and then Info.Tree_Id = SMB.Core_Wire.Encoded_U32 (Packet, 36))
       and then
         (if Command = 8 and then Nt_Status = SMB.Success then
            Packet'Length >= 80
            and then Natural (Packet (Packet'First + 66)) =
              Info.Data_Offset
            and then Info.Data_Length <= Maximum_IO_Chunk
            and then Info.Data_Length = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68))
          elsif Command = 9
            and then Nt_Status = SMB.Success
          then Packet'Length >= 80
            and then Info.Count <= Maximum_IO_Chunk
            and then Info.Count = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68))
          elsif Command = 14 and then Nt_Status = SMB.Success
          then Packet'Length >= 72
            and then Info.Data_Offset = Natural
              (SMB.Core_Wire.Encoded_U16 (Packet, 66))
            and then
              (Info.Data_Length = 0 or else Info.Data_Offset >= 72)
            and then Info.Data_Length <= Maximum_IO_Chunk
            and then Info.Data_Length = Natural
              (SMB.Core_Wire.Encoded_U32 (Packet, 68)))),
     Contract_Cases =>
       (Command = 0 and then Nt_Status = SMB.Success =>
          (if Status = SMB.Ok then
             Packet'Length >= 128
             and then Info.Dialect = SMB.Core_Wire.Encoded_U16 (Packet, 68)
             and then Info.Dialect in SMB.SMB2_Dialect_0210
                                    | SMB.SMB2_Dialect_0311
             and then Info.Data_Length =
               Natural (SMB.Core_Wire.Encoded_U16 (Packet, 122))
             and then
               (if Info.Data_Length = 0 then Info.Data_Offset = 0
                else Info.Data_Offset >= 128
                  and then Info.Data_Offset =
                    Natural (SMB.Core_Wire.Encoded_U16 (Packet, 120)))
           else True),
        (Command = 1 and then
           (Nt_Status = SMB.Success or else
              Nt_Status = SMB.Status_More_Processing_Required)) =>
          (if Status = SMB.Ok then
             Packet'Length >= 72
             and then Info.Session_Id /= 0
             and then Info.Session_Id =
               SMB.Core_Wire.Encoded_U64 (Packet, 40)
             and then (Info.Data_Length = 0 or else Info.Data_Offset >= 72)
             and then Info.Data_Offset =
               Natural (SMB.Core_Wire.Encoded_U16 (Packet, 68))
             and then Info.Data_Length =
               Natural (SMB.Core_Wire.Encoded_U16 (Packet, 70))
           else True),
        others => True);

   procedure Parse_Directory_Entry
     (Buffer : SMB.Bytes;
      Cursor : in out Natural;
      Info : out Directory_Info;
      Status : out SMB.Core_Status)
   with Pre => Buffer'Length <= SMB.Maximum_Frame_Size
     and then Cursor <= Buffer'Length,
     Post => Cursor <= Buffer'Length
       and then (if Status /= SMB.Ok then Cursor = Cursor'Old)
       and then (if Status = SMB.Ok then
         Cursor > Cursor'Old
         and then Buffer'Length - Cursor'Old >= 104
         and then
           ((Cursor = Buffer'Length) =
             (SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old) = 0))
         and then
           (if Cursor < Buffer'Length then
              SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old) <
                SMB.DWord (Buffer'Length - Cursor'Old)
              and then Cursor - Cursor'Old =
                Natural (SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old)))
         and then Info.Next_Cursor = Cursor
         and then Info.Name_Length > 0
         and then Info.Name_Offset <= Buffer'Length
         and then Info.Name_Length <= Buffer'Length - Info.Name_Offset
         and then Info.Name_Offset = Cursor'Old + 104
         and then Info.Name_Length = Natural
           (SMB.Core_Wire.Encoded_U32 (Buffer, Cursor'Old + 60))
         and then Info.Size =
           SMB.Core_Wire.Encoded_U64 (Buffer, Cursor'Old + 40)
         and then Info.Attributes = SMB.Core_Wire.Encoded_U32
           (Buffer, Cursor'Old + 56));

   procedure Advance_Transfer
     (Position : in out SMB.QWord;
      Remaining : in out Natural;
      Requested, Count : Natural;
      Status : out SMB.Core_Status;
      Require_Progress : Boolean := True)
   with Pre => Requested <= Maximum_IO_Chunk
     and then Count <= Maximum_IO_Chunk
     and then Remaining <= SMB.Maximum_Frame_Size,
     Post => Status =
       (if (Count = 0 and then Requested /= 0 and then Require_Progress)
          or else Count > Requested or else Count > Remaining'Old
        then SMB.Invalid_Value
        elsif SMB.QWord (Count) > SMB.QWord'Last - Position'Old
        then SMB.Invalid_Offset
        else SMB.Ok)
       and then Remaining <= Remaining'Old
       and then (if Status = SMB.Ok then
          Count <= Requested
          and then SMB.QWord (Count) <= SMB.QWord'Last - Position'Old
          and then Remaining = Remaining'Old - Count
          and then Position = Position'Old + SMB.QWord (Count)
        else Position = Position'Old
          and then Remaining = Remaining'Old);

   procedure Select_Transfer_Amount
     (Remaining, Limit : Natural;
      Amount : out Natural;
      Status : out SMB.Core_Status)
   with Pre => Remaining <= SMB.Maximum_Frame_Size
     and then Limit <= Maximum_IO_Chunk,
     Post => Status =
       (if Remaining /= 0 and then Limit = 0 then SMB.Invalid_Value
        else SMB.Ok)
       and then Amount <= Remaining
       and then Amount <= Limit
       and then (if Status = SMB.Ok
         then Amount = Natural'Min (Remaining, Limit)
         else Amount = 0);

   procedure Check_Transfer_Range
     (Base_Offset : SMB.QWord;
      Total : Natural;
      Status : out SMB.Core_Status)
   with Pre => Total <= SMB.Maximum_Frame_Size,
     Post => Status =
       (if SMB.QWord (Total) > SMB.QWord'Last - Base_Offset
        then SMB.Invalid_Offset
        else SMB.Ok);

   procedure Count_Directory_Page
     (Pages : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Pages <= Maximum_Directory_Pages,
     Post => Status =
       (if Pages'Old = Maximum_Directory_Pages then SMB.Resource_Limit
        else SMB.Ok)
       and then Pages <= Maximum_Directory_Pages
       and then (if Status = SMB.Ok then Pages = Pages'Old + 1
         else Pages = Pages'Old);

   procedure Count_Directory_Entry
     (Entries : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Entries <= Maximum_Directory_Entries,
     Post => Status =
       (if Entries'Old = Maximum_Directory_Entries then SMB.Resource_Limit
        else SMB.Ok)
       and then Entries <= Maximum_Directory_Entries
       and then (if Status = SMB.Ok then Entries = Entries'Old + 1
         else Entries = Entries'Old);
end SMB.Core_Protocol;
