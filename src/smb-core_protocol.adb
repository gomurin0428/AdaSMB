with SMB.Core_Text;

package body SMB.Core_Protocol with SPARK_Mode is
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

   procedure Clear (Output : out SMB.Bytes)
   with Post =>
     (for all Index in Output'Range => Output (Index) = 0)
   is
   begin
      Output := (others => 0);
   end Clear;

   procedure Put_Byte
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.Byte;
      Status : in out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             Position < Output'Length
             and then Output (Output'First + Position) = Value
             and then
               (if Position > 0 then
                  Output (Output'First .. Output'First + (Position - 1)) =
                    Output'Old
                      (Output'First .. Output'First + (Position - 1)))
             and then
               (for all Index in Output'Range =>
                  (if Index - Output'First /= Position
                   then Output (Index) = Output'Old (Index)))
           else Output = Output'Old)
          and then
            (if Status'Old /= SMB.Ok then Status = Status'Old);

   procedure Put_Byte
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.Byte;
      Status : in out SMB.Core_Status) is
   begin
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: Begin_Build already rejected a buffer too small for the body
         if Position >= Output'Length then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := SMB.Resource_Limit;
         else
            Output (Output'First + Position) := Value;
         end if;
      end if;
   end Put_Byte;

   procedure Copy
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.Bytes;
      Status : out SMB.Core_Status)
   with Pre =>
     Output'Length <= SMB.Maximum_Frame_Size
     and then Value'Length <= SMB.Maximum_Frame_Size,
     Post =>
       (if Status = SMB.Ok then
          Position <= Output'Length
          and then Value'Length <= Output'Length - Position
          and then
            (if Value'Length > 0 then
               Output (Output'First + Position ..
                       Output'Last -
                         (Output'Length - Position - Value'Length)) = Value)
          and then
          (if Position >= 8 and then Output'Length >= 8 then
             SMB.Core_Wire.Encoded_U32 (Output, 4) =
               SMB.Core_Wire.Encoded_U32 (Output'Old, 4))
          and then
          (if Value'Length > 0 then
             (for all Index in 0 .. Value'Length - 1 =>
                Output (Output'First + Position + Index) =
                  Value (Value'First + Index))
           else Position <= Output'Length)
          and then
            (for all Index in Output'Range =>
               (if Value'Length = 0
                  or else Index - Output'First < Position
                  or else Index - Output'First >= Position + Value'Length
                then Output (Index) = Output'Old (Index)))
          and then
            (if Position > 0 then
               Output (Output'First .. Output'First + (Position - 1)) =
                 Output'Old
                   (Output'First .. Output'First + (Position - 1))
               and then
               (for all Index in 0 .. Position - 1 =>
                  Output (Output'First + Index) =
                    Output'Old (Output'First + Index)))
        else Output = Output'Old);

   procedure Copy
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.Bytes;
      Status : out SMB.Core_Status) is
   begin
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: Begin_Build already rejected a buffer too small for the body
      if Position > Output'Length
        --  adamutant:disable-next-line LogicalOperator, ArithmeticOperator: unreachable, as above
        or else Value'Length > Output'Length - Position
      then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Resource_Limit;
         return;
      end if;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: copying nothing changes nothing
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
      Status : in out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             SMB.Core_Wire.Encoded_U16 (Output, Position) = Value
             and then
               (if Position >= 8 and then Output'Length >= 8 then
                  SMB.Core_Wire.Encoded_U32 (Output, 4) =
                    SMB.Core_Wire.Encoded_U32 (Output'Old, 4))
             and then
               (for all Index in Output'Range =>
                  (if Index - Output'First < Position
                     or else Index - Output'First >= Position + 2
                   then Output (Index) = Output'Old (Index)))
           else Output = Output'Old)
          and then
            (if Status'Old /= SMB.Ok then Status = Status'Old)
   is
   begin
      if Status = SMB.Ok then
         SMB.Core_Wire.Write_U16 (Output, Position, Value, Status);
      end if;
   end Put_U16;

   procedure Put_U32
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.DWord;
      Status : in out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             SMB.Core_Wire.Encoded_U32 (Output, Position) = Value
             and then
               (if Position >= 8 and then Output'Length >= 8 then
                  SMB.Core_Wire.Encoded_U32 (Output, 4) =
                    SMB.Core_Wire.Encoded_U32 (Output'Old, 4))
             and then
               (for all Byte_Index in 0 .. 3 =>
                  Output
                    (Output'First + Position + Byte_Index) =
                    SMB.Core_Wire.U32_Byte (Value, Byte_Index))
             and then
               (for all Index in Output'Range =>
                  (if Index - Output'First < Position
                     or else Index - Output'First >= Position + 4
                   then Output (Index) = Output'Old (Index)))
           else Output = Output'Old)
          and then
            (if Status'Old /= SMB.Ok then Status = Status'Old)
   is
   begin
      if Status = SMB.Ok then
         SMB.Core_Wire.Write_U32 (Output, Position, Value, Status);
      end if;
   end Put_U32;

   procedure Put_U64
     (Output : in out SMB.Bytes;
      Position : Natural;
      Value : SMB.QWord;
      Status : in out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             SMB.Core_Wire.Encoded_U64 (Output, Position) = Value
             and then
               (for all Byte_Index in 0 .. 7 =>
                  Output (Output'First + Position + Byte_Index) =
                    SMB.Core_Wire.U64_Byte (Value, Byte_Index))
             and then
               (for all Index in Output'Range =>
                  (if Index - Output'First < Position
                     or else Index - Output'First >= Position + 8
                   then Output (Index) = Output'Old (Index)))
           else Output = Output'Old)
          and then
            (if Status'Old /= SMB.Ok then Status = Status'Old)
   is
   begin
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         SMB.Core_Wire.Write_U64 (Output, Position, Value, Status);
      end if;
   end Put_U64;

   procedure Begin_Build
     (Output : out SMB.Bytes;
      Required : Natural;
      Status : out SMB.Core_Status)
   with Pre => Output'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             Required <= Output'Length
             and then
               (for all Index in Output'Range => Output (Index) = 0)
           else Required > Output'Length)
   is
   begin
      Status := SMB.Ok;
      Clear (Output);
      --  adamutant:disable-next-line ConditionalExpression: the field write past the end, or Finish, reports the same Resource_Limit
      if Required > Output'Length then
         --  adamutant:disable-next-line StatementDeletion: the field write past the end, or Finish, reports the same Resource_Limit
         Status := SMB.Resource_Limit;
      end if;
   end Begin_Build;

   procedure Finish
     (Required : Natural;
      Capacity : Natural;
      Used : out Natural;
      Status : in out SMB.Core_Status)
   with Pre => Capacity <= SMB.Maximum_Frame_Size,
        Post =>
          Used <= Capacity
          and then
            (if Status = SMB.Ok
             then Used = Required and then Required <= Capacity
             else Used = 0)
          and then
            (if Status'Old /= SMB.Ok then Status = Status'Old)
   is
   begin
      if Status = SMB.Ok and then Required <= Capacity then
         Used := Required;
      else
         --  adamutant:disable-next-line ConditionalExpression: Begin_Build already set Resource_Limit for a body that does not fit
         if Status = SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := SMB.Resource_Limit;
         end if;
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
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: Begin_Build cleared the buffer
      Put_U32 (Output, 8, 0, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Copy (Output, 12, Guid, Status);
      end if;
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: Begin_Build cleared the buffer
      Put_U64 (Output, 28, 0, Status);
      Put_U16 (Output, 36, SMB.SMB2_Dialect_0210, Status);
      Finish (38, Output'Length, Used, Status);
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
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion, NumericLiteral: Begin_Build cleared the buffer
         Put_Byte (Output, 2, 0, Status);
         Put_Byte (Output, 3, 3, Status);
      end if;
      Put_U16 (Output, 12, 88, Status);
      --  adamutant:disable-next-line ConditionalExpression: the precondition limits the token to SMB.Word'Last bytes
      if Token'Length > SMB.Word'Last then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Resource_Limit;
      else
         Put_U16 (Output, 14, SMB.Word (Token'Length), Status);
         --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
         if Status = SMB.Ok then
            Copy (Output, 24, Token, Status);
         end if;
      end if;
      Finish (Required, Output'Length, Used, Status);
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
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: the precondition limits the name to Maximum_Name_Bytes
      elsif Name'Length > SMB.Word'Last then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Resource_Limit;
      else
         Put_U16 (Output, 6, SMB.Word (Name'Length), Status);
         --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
         if Status = SMB.Ok then
            Copy (Output, 8, Name, Status);
         end if;
      end if;
      Finish (Required, Output'Length, Used, Status);
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
      Put_U32 (Output, 32, 7, Status);
      Put_U16 (Output, 44, 120, Status);
      if Name'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: the precondition limits the name to Maximum_Name_Bytes
      elsif Name'Length > SMB.Word'Last then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Resource_Limit;
      else
         --  adamutant:disable-next-line ConditionalExpression, LogicalOperator, EqualityOperator, NumericLiteral: an empty or odd name copies nothing that is used
         if Status = SMB.Ok and then Name'Length > 0 then
            Copy (Output, 56, Name, Status);
         end if;
      end if;
      Finish (Required, Output'Length, Used, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Output (Output'First + 24 .. Output'First + 31) :=
           (SMB.Core_Wire.U32_Byte (Access_Mask, 0),
            SMB.Core_Wire.U32_Byte (Access_Mask, 1),
            SMB.Core_Wire.U32_Byte (Access_Mask, 2),
            SMB.Core_Wire.U32_Byte (Access_Mask, 3),
            SMB.Core_Wire.U32_Byte
              ((if Directory then 16#10# else 0), 0),
            SMB.Core_Wire.U32_Byte
              --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the attributes fit in the first byte
              ((if Directory then 16#10# else 0), 1),
            SMB.Core_Wire.U32_Byte
              --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the attributes fit in the first byte
              ((if Directory then 16#10# else 0), 2),
            SMB.Core_Wire.U32_Byte
              --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the attributes fit in the first byte
              ((if Directory then 16#10# else 0), 3));
         Output (Output'First + 36 .. Output'First + 39) :=
           (SMB.Core_Wire.U32_Byte (Disposition, 0),
            SMB.Core_Wire.U32_Byte (Disposition, 1),
            SMB.Core_Wire.U32_Byte (Disposition, 2),
            SMB.Core_Wire.U32_Byte (Disposition, 3));
         Output (Output'First + 40 .. Output'First + 43) :=
           (SMB.Core_Wire.U32_Byte
              ((if Directory then 1 else 16#40#), 0),
            SMB.Core_Wire.U32_Byte
              --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the options fit in the first byte
              ((if Directory then 1 else 16#40#), 1),
            SMB.Core_Wire.U32_Byte
              --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the options fit in the first byte
              ((if Directory then 1 else 16#40#), 2),
            SMB.Core_Wire.U32_Byte
              --  adamutant:disable-next-line ConditionalExpression, NumericLiteral: the options fit in the first byte
              ((if Directory then 1 else 16#40#), 3));
         Output (Output'First + 46 .. Output'First + 47) :=
           (SMB.Core_Wire.U16_Byte (SMB.Word (Name'Length), 0),
            SMB.Core_Wire.U16_Byte (SMB.Word (Name'Length), 1));
      end if;
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
      Put_Byte
        (Output, 4, SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 0), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 4) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 0));
      Put_Byte
        (Output, 5, SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 1), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 5) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 1));
      Put_Byte
        (Output, 6, SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 2), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 6) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 2));
      --  adamutant:disable-next-line StatementDeletion: Amount is at most 65,536, so its top byte is 0
      Put_Byte
        --  adamutant:disable-next-line NumericLiteral: Amount is at most 65,536, so its top byte is 0
        (Output, 7, SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 3), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 7) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Amount), 3));
      Put_U64 (Output, 8, Offset, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Output (Output'First + 16 .. Output'First + 31) := File_Id;
      end if;
      pragma Assert
        (if Status = SMB.Ok then
           (for all Index in 0 .. 15 =>
              Output (Output'First + 16 + Index) =
                File_Id (File_Id'First + Index)));
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: Begin_Build cleared the buffer
      Put_U32 (Output, 32, 0, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Put_Byte (Output, 48, 1, Status);
      end if;
      Finish (49, Output'Length, Used, Status);
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
      Put_Byte
        (Output, 4, SMB.Core_Wire.U32_Byte
           (SMB.DWord (Data'Length), 0), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 4) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 0));
      Put_Byte
        (Output, 5, SMB.Core_Wire.U32_Byte
           (SMB.DWord (Data'Length), 1), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 5) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 1));
      Put_Byte
        (Output, 6, SMB.Core_Wire.U32_Byte
           (SMB.DWord (Data'Length), 2), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 6) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 2));
      --  adamutant:disable-next-line StatementDeletion: the data is at most 65,536 bytes, so the top byte of its length is 0
      Put_Byte
        --  adamutant:disable-next-line NumericLiteral: the data is at most 65,536 bytes, so the top byte of its length is 0
        (Output, 7, SMB.Core_Wire.U32_Byte
           (SMB.DWord (Data'Length), 3), Status);
      pragma Assert
        (if Status = SMB.Ok then
           Output (Output'First + 7) =
             SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 3));
      Put_U64 (Output, 8, Offset, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Copy (Output, 16, File_Id, Status);
      end if;
      pragma Assert
        (if Status = SMB.Ok then
           (for all Index in 0 .. 15 =>
              Output (Output'First + 16 + Index) =
                File_Id (File_Id'First + Index)));
      --  Keep only what the rest needs: the eight header calls before this
      --  point leave a chain of frame conditions that makes the provers time
      --  out on the data copy below.
      pragma Assert_And_Cut
        (Output'Length <= SMB.Maximum_Frame_Size
         and then Data'Length <= Maximum_IO_Chunk
         and then File_Id'Length = 16
         and then Required = 48 + Data'Length
         and then
           (if Status = SMB.Ok then
              Required <= Output'Length
              and then Output (Output'First + 4) =
                SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 0)
              and then Output (Output'First + 5) =
                SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 1)
              and then Output (Output'First + 6) =
                SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 2)
              and then Output (Output'First + 7) =
                SMB.Core_Wire.U32_Byte (SMB.DWord (Data'Length), 3)
              and then SMB.Core_Wire.Encoded_U64 (Output, 8) = Offset
              and then
                (for all Byte_Index in 0 .. 7 =>
                   Output (Output'First + 8 + Byte_Index) =
                     SMB.Core_Wire.U64_Byte (Offset, Byte_Index))
              and then
                (for all Index in 0 .. 15 =>
                   Output (Output'First + 16 + Index) =
                     File_Id (File_Id'First + Index))));
      --  Bytes 44 to 47 (Flags) stay zero, as Begin_Build cleared them.
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Copy (Output, 48, Data, Status);
      end if;
      pragma Assert
        (if Status = SMB.Ok and then Data'Length > 0 then
           (for all Index in 0 .. Data'Length - 1 =>
              Output (Output'First + 48 + Index) = Data (Data'First + Index)));
      Finish (Required, Output'Length, Used, Status);
   end Build_Write;

   procedure Build_Close
     (File_Id : SMB.Bytes;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      --  adamutant:disable-next-line ConditionalExpression: Begin_Build and Finish reject a short buffer the same way
      if Output'Length < 24 then
         Clear (Output);
         Used := 0;
         Status := SMB.Resource_Limit;
         return;
      end if;
      Begin_Build (Output, 24, Status);
      Put_U16 (Output, 0, 24, Status);
      Finish (24, Output'Length, Used, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Output (Output'First + 8 .. Output'First + 23) := File_Id;
      end if;
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
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Put_Byte (Output, 2, 37, Status);
         Put_Byte (Output, 3, (if Restart then 1 else 0), Status);
      end if;
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Output (Output'First + 8 .. Output'First + 23) := File_Id;
      end if;
      Put_U16 (Output, 24, 96, Status);
      Put_U16 (Output, 26, 2, Status);
      Put_U32 (Output, 28, Maximum_IO_Chunk, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Put_Byte (Output, 32, 16#2A#, Status);
         --  adamutant:disable-next-line StatementDeletion: Begin_Build cleared the buffer
         Put_Byte (Output, 33, 0, Status);
      end if;
      Finish (Required, Output'Length, Used, Status);
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
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Put_Byte (Output, 2, 1, Status);
         Put_Byte (Output, 3, 13, Status);
      end if;
      Put_U32 (Output, 4, 1, Status);
      Put_U16 (Output, 8, 96, Status);
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Copy (Output, 16, File_Id, Status);
         Put_Byte
           (Output, 32, (if Delete_File then 1 else 0), Status);
      end if;
      Finish (33, Output'Length, Used, Status);
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
      --  adamutant:disable-next-line ConditionalExpression: the status is Ok here whenever the output is used
      if Status = SMB.Ok then
         Put_Byte (Output, 2, 1, Status);
         Put_Byte (Output, 3, 10, Status);
      end if;
      if Name'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator, ArithmeticOperator, NumericLiteral: the precondition limits the name to Maximum_Name_Bytes
      elsif Name'Length > SMB.DWord'Last - 20 then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Resource_Limit;
      else
         Put_U32 (Output, 4, SMB.DWord (20 + Name'Length), Status);
      end if;
      Put_U16 (Output, 8, 96, Status);
      if Status = SMB.Ok then
         Copy (Output, 16, File_Id, Status);
      end if;
      Put_U32 (Output, 48, SMB.DWord (Name'Length), Status);
      if Status = SMB.Ok then
         Copy (Output, 52, Name, Status);
      end if;
      Finish (Required, Output'Length, Used, Status);
      --  Copy states the name's slice with its upper bound counted from
      --  Output'Last; the postcondition counts it from Used.
      pragma Assert
        (if Status = SMB.Ok and then Name'Length > 0 then
           Used = 52 + Name'Length
           and then Output'Last - (Output'Length - 52 - Name'Length) =
             Output'First + (Used - 1));
   end Build_Rename;

   procedure Build_Simple
     (Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
   begin
      Begin_Build (Output, 4, Status);
      Put_U16 (Output, 0, 4, Status);
      Finish (4, Output'Length, Used, Status);
   end Build_Simple;

   function Fits
     (Value : SMB.DWord; Available : Natural) return Boolean is
     (SMB.QWord (Value) <= SMB.QWord (Available));

   procedure Read_U16
     (Packet : SMB.Bytes; Offset : Natural; Value : out SMB.Word;
      Status : in out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             Offset <= Packet'Length
             and then Packet'Length - Offset >= 2
             and then
             Value = SMB.Core_Wire.Encoded_U16 (Packet, Offset)
           else Value = 0)
   is
   begin
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: callers read the value only after a success
      Value := 0;
      --  adamutant:disable-next-line ConditionalExpression: callers read the value only after a success
      if Status = SMB.Ok then
         SMB.Core_Wire.Read_U16 (Packet, Offset, Value, Status);
      end if;
   end Read_U16;

   procedure Read_U32
     (Packet : SMB.Bytes; Offset : Natural; Value : out SMB.DWord;
      Status : in out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             Offset <= Packet'Length
             and then Packet'Length - Offset >= 4
             and then Value = SMB.Core_Wire.Encoded_U32 (Packet, Offset))
   is
   begin
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: callers read the value only after a success
      Value := 0;
      --  adamutant:disable-next-line ConditionalExpression: callers read the value only after a success
      if Status = SMB.Ok then
         --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: callers check the packet length first
         if Offset > Packet'Length
           --  adamutant:disable-next-line LogicalOperator, ArithmeticOperator: callers check the packet length first
           or else Packet'Length - Offset < 4
         then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := SMB.Invalid_Offset;
         else
            SMB.Core_Wire.Read_U32 (Packet, Offset, Value, Status);
         end if;
      end if;
   end Read_U32;

   procedure Read_U64
     (Packet : SMB.Bytes; Offset : Natural; Value : out SMB.QWord;
      Status : in out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size,
        Post =>
          (if Status = SMB.Ok then
             Offset <= Packet'Length
             and then Packet'Length - Offset >= 8
             and then Value = SMB.Core_Wire.Encoded_U64 (Packet, Offset))
   is
   begin
      --  adamutant:disable-next-line StatementDeletion, NumericLiteral: callers read the value only after a success
      Value := 0;
      --  adamutant:disable-next-line ConditionalExpression: callers read the value only after a success
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
      --  adamutant:disable-next-line NumericLiteral: written before it is read; the value is for flow analysis
      Count : SMB.Word := 0;
      --  adamutant:disable-next-line NumericLiteral: written before it is read; the value is for flow analysis
      Byte_Count : SMB.DWord := 0;
      --  adamutant:disable-next-line NumericLiteral: written before it is read; the value is for flow analysis
      Available : Natural := 0;
   begin
      --  adamutant:disable-next-line StatementDeletion: every field read later is written first
      Info := (others => <>);
      Status := SMB.Ok;
      if Packet'Length < 72 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Available := Packet'Length - 72;
      if Packet (Packet'First + 66) /= 0 then
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
      --  adamutant:disable-next-line NumericLiteral: written before it is read; the value is for flow analysis
      Structure : SMB.Word := 0;
      --  adamutant:disable-next-line NumericLiteral: written before it is read; the value is for flow analysis
      Word_Value : SMB.Word := 0;
      --  adamutant:disable-next-line NumericLiteral: written before it is read; the value is for flow analysis
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
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator, NumericLiteral: each command branch requires a longer packet
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
         Read_U16 (Packet, 68, Info.Dialect, Header_Status);
         if Info.Dialect /= SMB.SMB2_Dialect_0210
           and then Info.Dialect /= SMB.SMB2_Dialect_0311
         then
            Status := SMB.Unsupported_Feature;
            return;
         end if;
         Read_U64 (Packet, 40, Info.Session_Id, Header_Status);
         Read_U32 (Packet, 36, Info.Tree_Id, Header_Status);
         Read_U32 (Packet, 88, DWord_Value, Header_Status);
         --  Multichannel, persistent handles, directory leasing and
         --  encryption (16#78#) are SMB 3 capabilities: a 2.1 server must
         --  not claim them, and a 3.1.1 server may, though we use none.
         if Info.Session_Id /= 0 or else Info.Tree_Id /= 0
           or else (Info.Dialect = SMB.SMB2_Dialect_0210
                    and then (DWord_Value and 16#78#) /= 0)
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         DWord_Value := SMB.Core_Wire.Encoded_U32 (Packet, 96);
         if DWord_Value = 0 then
            Status := SMB.Invalid_Value;
            return;
         end if;
         Info.Max_Read :=
           Natural (SMB.DWord'Min (Maximum_IO_Chunk, DWord_Value));
         DWord_Value := SMB.Core_Wire.Encoded_U32 (Packet, 100);
         if DWord_Value = 0 then
            Status := SMB.Invalid_Value;
            return;
         end if;
         Info.Max_Write :=
           Natural (SMB.DWord'Min (Maximum_IO_Chunk, DWord_Value));
         Read_U16 (Packet, 120, Word_Value, Header_Status);
         Read_U16 (Packet, 122, Structure, Header_Status);
         --  adamutant:disable-next-line ConditionalExpression: the packet length was checked, so the reads succeed
         if Header_Status /= SMB.Ok then
            --  adamutant:disable-next-line StatementDeletion: unreachable, as above
            Status := Header_Status;
            return;
         end if;
         --  An offset past the end is wrong even for an empty token, which
         --  the final bounds check never sees.
         if SMB.QWord (Word_Value) > SMB.QWord (Packet'Length)
           or else SMB.QWord (Structure) >
             --  adamutant:disable-next-line ArithmeticOperator: a token past the end fails the final bounds check as well
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
         if Structure /= 9
           or else (Word_Value /= 0 and then Word_Value /= 4)
           or else Info.Session_Id = 0
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Info.Encrypt_Data := Word_Value = 4;
         Offset := Natural (SMB.Core_Wire.Encoded_U16 (Packet, 68));
         Length := Natural (SMB.Core_Wire.Encoded_U16 (Packet, 70));
         if Length > 0 and then Offset < 72 then
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
         Info.Tree_Id := SMB.Core_Wire.Encoded_U32 (Packet, 36);
         if Structure /= 16 or else Packet (Packet'First + 66) /= 1
           or else Info.Tree_Id = 0
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         Info.Encrypt_Data := (DWord_Value and 16#8000#) /= 0;
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
         --  adamutant:disable-next-line ConditionalExpression: the check below rejects the same offsets
         if not Fits (DWord_Value, Packet'Length) then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         Offset := Natural (DWord_Value);
         --  Fits above already bounds the offset; this check is for the prover.
         --  adamutant:disable ConditionalExpression, EqualityOperator, StatementDeletion
         if Offset > Packet'Length then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         --  adamutant:enable ConditionalExpression, EqualityOperator, StatementDeletion
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
         if Structure /= 17 then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Offset := Natural (Packet (Packet'First + 66));
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         if DWord_Value > SMB.DWord (Maximum_IO_Chunk)
           --  adamutant:disable-next-line LogicalOperator, NumericLiteral: the test before it reads the same field
           or else SMB.Core_Wire.Encoded_U32 (Packet, 68) >
             SMB.DWord (Maximum_IO_Chunk)
         then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Length := Natural (DWord_Value);
         if Length > 0 and then Offset < 80
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
         Read_U32 (Packet, 68, DWord_Value, Header_Status);
         if Structure /= 17 or else DWord_Value = 0
           or else DWord_Value > SMB.DWord (Maximum_IO_Chunk)
           or else SMB.Core_Wire.Encoded_U32 (Packet, 68) >
             SMB.DWord (Maximum_IO_Chunk)
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Info.Count :=
           Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68));
      elsif Command = Close_Command then
         if Packet'Length < 124 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Word_Value := SMB.Core_Wire.Encoded_U16 (Packet, 66);
         if Structure /= 60 or else (Word_Value and 16#FFFE#) /= 0 then
            Status := SMB.Invalid_Protocol;
         end if;
      elsif Command = 14 then
         if Packet'Length < 72 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         Word_Value := SMB.Core_Wire.Encoded_U16 (Packet, 66);
         DWord_Value := SMB.Core_Wire.Encoded_U32 (Packet, 68);
         if Structure /= 9
           or else DWord_Value > SMB.DWord (Maximum_IO_Chunk)
         then
            Status := SMB.Invalid_Protocol;
            return;
         end if;
         Offset := Natural (Word_Value);
         Length := Natural (DWord_Value);
         if Length > 0 and then Offset < 72
         then
            Status := SMB.Invalid_Offset;
            return;
         end if;
         Info.Data_Offset :=
           Natural (SMB.Core_Wire.Encoded_U16 (Packet, 66));
         Info.Data_Length :=
           Natural (SMB.Core_Wire.Encoded_U32 (Packet, 68));
      elsif Command = Set_Info_Command then
         if Packet'Length < 66 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         if Structure /= 2 then
            Status := SMB.Invalid_Protocol;
         end if;
      --  adamutant:disable-next-line ConditionalExpression: the case at the start rejects every other command
      elsif Command = Tree_Disconnect_Command
        or else Command = Logoff_Command
      then
         if Packet'Length < 68 then
            Status := SMB.Invalid_Length;
            return;
         end if;
         Read_U16 (Packet, 64, Structure, Header_Status);
         if Structure /= 4 then
            Status := SMB.Invalid_Protocol;
         end if;
      else
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := SMB.Unsupported_Feature;
      end if;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator, LogicalOperator: the packet length was checked, so the reads succeed
      if Header_Status /= SMB.Ok and then Status = SMB.Ok then
         --  adamutant:disable-next-line StatementDeletion: unreachable, as above
         Status := Header_Status;
      end if;
      --  The one bounds check of the data that a branch above recorded.
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
   begin
      --  adamutant:disable-next-line StatementDeletion: every field read later is written first
      Info := (others => <>);
      Status := SMB.Ok;
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: fewer than 104 bytes fail the next check the same way
      if Cursor >= Buffer'Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Remaining := Buffer'Length - Cursor;
      --  adamutant:disable-next-line EqualityOperator, NumericLiteral: an entry of 104 bytes has no room for the name it needs
      if Remaining < 104 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Next_Offset := SMB.Core_Wire.Encoded_U32 (Buffer, Cursor);
      Info.Size := SMB.Core_Wire.Encoded_U64 (Buffer, Cursor + 40);
      Info.Attributes :=
        SMB.Core_Wire.Encoded_U32 (Buffer, Cursor + 56);
      Name_Length := SMB.Core_Wire.Encoded_U32 (Buffer, Cursor + 60);
      Short_Name_Length := Buffer (Buffer'First + Cursor + 68);
      --  adamutant:disable-next-line ArithmeticOperator: a longer name fails the entry length check below the same way
      if not Fits (Name_Length, Remaining - 104)
        --  adamutant:disable-next-line LogicalOperator: a longer name fails the entry length check below the same way
        or else not Fits (Name_Length, Maximum_Name_Bytes)
        or else Name_Length = 0
        --  adamutant:disable-next-line NumericLiteral: an odd short name fails the next check the same way
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
      --  adamutant:disable-next-line EqualityOperator: the entry length check below rejects the same offsets
      elsif Next_Offset >= SMB.DWord (Remaining)
        --  adamutant:disable-next-line EqualityOperator, NumericLiteral, LogicalOperator: an entry of 104 bytes has no room for the name it needs, and the entry length check rejects the rest
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
        --  adamutant:disable-next-line LogicalOperator: the checks above already bound the entry length
        or else (Next_Offset /= 0 and then Entry_Length = Remaining)
        or else Natural (Name_Length) > Entry_Length - 104
      then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      Name_Offset_Value := Cursor + 104;
      Name_Length_Value := Natural (Name_Length);
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
