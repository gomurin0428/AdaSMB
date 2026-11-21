package body SMB.Core_Text is
   pragma SPARK_Mode (On);

   package U renames SMB.Spec.Unicode with Ghost;

   function Byte_At (Value : String; Offset : Natural) return Natural
     with Pre => Offset < Value'Length,
       Post => Byte_At'Result <= 255
         and then Byte_At'Result =
           Character'Pos (Value (Value'First + Offset));

   function Byte_At (Value : String; Offset : Natural) return Natural is
     (Character'Pos (Value (Value'First + Offset)));

   --  Zero denotes an invalid or missing scalar under the SMB no-NUL policy.
   function UTF8_Scalar_At (Value : String; Position : Natural) return Natural is
     (if Position = Value'Length then 0
      elsif Byte_At (Value, Position) in 1 .. 16#7F# then
         Byte_At (Value, Position)
      elsif Value'Length - Position >= 2
        and then Byte_At (Value, Position) in 16#C2# .. 16#DF#
        and then Byte_At (Value, Position + 1) in 16#80# .. 16#BF#
      then
         (Byte_At (Value, Position) mod 32) * 64
         + Byte_At (Value, Position + 1) mod 64
      elsif Value'Length - Position >= 3
        and then Byte_At (Value, Position) in 16#E0# .. 16#EF#
        and then
          (if Byte_At (Value, Position) = 16#E0# then
              Byte_At (Value, Position + 1) in 16#A0# .. 16#BF#
           elsif Byte_At (Value, Position) = 16#ED# then
              Byte_At (Value, Position + 1) in 16#80# .. 16#9F#
           else Byte_At (Value, Position + 1) in 16#80# .. 16#BF#)
        and then Byte_At (Value, Position + 2) in 16#80# .. 16#BF#
      then
         (Byte_At (Value, Position) mod 16) * 4_096
         + (Byte_At (Value, Position + 1) mod 64) * 64
         + Byte_At (Value, Position + 2) mod 64
      elsif Value'Length - Position >= 4
        and then Byte_At (Value, Position) in 16#F0# .. 16#F4#
        and then
          (if Byte_At (Value, Position) = 16#F0# then
              Byte_At (Value, Position + 1) in 16#90# .. 16#BF#
           elsif Byte_At (Value, Position) = 16#F4# then
              Byte_At (Value, Position + 1) in 16#80# .. 16#8F#
           else Byte_At (Value, Position + 1) in 16#80# .. 16#BF#)
        and then Byte_At (Value, Position + 2) in 16#80# .. 16#BF#
        and then Byte_At (Value, Position + 3) in 16#80# .. 16#BF#
      then
         (Byte_At (Value, Position) mod 8) * 262_144
         + (Byte_At (Value, Position + 1) mod 64) * 4_096
         + (Byte_At (Value, Position + 2) mod 64) * 64
         + Byte_At (Value, Position + 3) mod 64
      else 0)
   with Ghost,
     Pre => Value'Length <= SMB.Maximum_Frame_Size
       and then Position <= Value'Length;

   function UTF16_Scalar_At
     (Input : SMB.Bytes; Position : Natural) return Natural is
     (if Input'Length - Position < 2 then 0
      elsif UTF16_Unit (Input, Position / 2) = 0 then 0
      elsif UTF16_Unit (Input, Position / 2) in 16#D800# .. 16#DBFF# then
         (if Input'Length - Position >= 4
           and then UTF16_Unit (Input, Position / 2 + 1)
             in 16#DC00# .. 16#DFFF#
          then
             16#10000#
             + (UTF16_Unit (Input, Position / 2) mod 1_024) * 1_024
             + UTF16_Unit (Input, Position / 2 + 1) mod 1_024
          else 0)
      elsif UTF16_Unit (Input, Position / 2) in 16#DC00# .. 16#DFFF# then 0
      else UTF16_Unit (Input, Position / 2))
   with Ghost,
     Pre => Input'Length <= SMB.Maximum_Frame_Size
       and then Position <= Input'Length
       and then Position mod 2 = 0;

   procedure Lemma_Invalid_UTF16_Unit (Input : SMB.Bytes; Index : Natural)
     with Ghost,
       Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
         and then Index < Input'Length / 2
         and then not Valid_UTF16_Unit (Input, Index),
       Post => not Valid_UTF16_Text (Input);

   procedure Lemma_Invalid_UTF16_Unit (Input : SMB.Bytes; Index : Natural) is
   begin
      null;
   end Lemma_Invalid_UTF16_Unit;

   procedure Lemma_Valid_UTF16_Prefix (Input : SMB.Bytes; Length : Natural)
     with Ghost,
       Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
         and then Length <= Input'Length and then Length mod 2 = 0
         and then
           (if Length > 0 then
              (for all Index in 0 .. Length / 2 - 1 =>
                 Valid_UTF16_Unit (Input, Index))
              and then UTF16_Unit (Input, Length / 2 - 1)
                not in 16#D800# .. 16#DBFF#),
       Post =>
         (if Length > 0 then
            Valid_UTF16_Text (Input (Input'First .. Input'First + (Length - 1))));

   procedure Lemma_Valid_UTF16_Prefix (Input : SMB.Bytes; Length : Natural) is
      pragma Unreferenced (Length);
   begin
      null;
   end Lemma_Valid_UTF16_Prefix;

   procedure Decode_UTF8
     (Value : String;
      Position : in out Natural;
      Scalar : out Natural;
      Status : out SMB.Core_Status)
     with Pre => Value'Length <= SMB.Maximum_Frame_Size
       and then Position <= Value'Length,
       Post => Position <= Value'Length
         and then Scalar = UTF8_Scalar_At (Value, Position'Old)
         and then Status =
           (if Scalar = 0 then SMB.Invalid_Encoding else SMB.Ok)
         and then Position = Position'Old +
           (if Scalar = 0 then 0
            elsif Scalar <= 16#7F# then 1
            elsif Scalar <= 16#7FF# then 2
            elsif Scalar <= 16#FFFF# then 3
            else 4)
         and then (if Status = SMB.Ok then
           Position > Position'Old and then Scalar in 1 .. 16#10FFFF#
           and then Scalar not in 16#D800# .. 16#DFFF#
           and then (if Scalar > 16#FFFF# then Position = Position'Old + 4))
         --  In the specification's terms (Unicode 16.0, Table 3-7).
         and then Status =
           (if U.Valid_UTF8_At (Value, Position'Old) then SMB.Ok
            else SMB.Invalid_Encoding)
         and then
           (if Status = SMB.Ok then
              Scalar = U.UTF8_Scalar (Value, Position'Old)
              and then Position =
                Position'Old + U.UTF8_Length (Value, Position'Old));

   procedure Decode_UTF8
     (Value : String;
      Position : in out Natural;
      Scalar : out Natural;
      Status : out SMB.Core_Status) is
      B1 : Natural;
      B2, B3, B4 : Natural;
      Remaining : Natural;
   begin
      Scalar := 0;
      if Position >= Value'Length then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Remaining := Value'Length - Position;
      B1 := Byte_At (Value, Position);
      if B1 = 0 then
         Status := SMB.Invalid_Encoding;
      elsif B1 <= 16#7F# then
         Scalar := B1;
         Position := Position + 1;
         Status := SMB.Ok;
      elsif B1 in 16#C2# .. 16#DF# then
         if Remaining < 2 then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         B2 := Byte_At (Value, Position + 1);
         if B2 not in 16#80# .. 16#BF# then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Scalar := (B1 - 16#C0#) * 64 + B2 - 16#80#;
         Position := Position + 2;
         Status := SMB.Ok;
      elsif B1 in 16#E0# .. 16#EF# then
         if Remaining < 3 then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         B2 := Byte_At (Value, Position + 1);
         B3 := Byte_At (Value, Position + 2);
         if B2 not in 16#80# .. 16#BF#
           or else B3 not in 16#80# .. 16#BF#
           or else (B1 = 16#E0# and then B2 < 16#A0#)
           or else (B1 = 16#ED# and then B2 >= 16#A0#)
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Scalar := (B1 - 16#E0#) * 4_096
           + (B2 - 16#80#) * 64 + B3 - 16#80#;
         Position := Position + 3;
         Status := SMB.Ok;
      elsif B1 in 16#F0# .. 16#F4# then
         if Remaining < 4 then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         B2 := Byte_At (Value, Position + 1);
         B3 := Byte_At (Value, Position + 2);
         B4 := Byte_At (Value, Position + 3);
         if B2 not in 16#80# .. 16#BF#
           or else B3 not in 16#80# .. 16#BF#
           or else B4 not in 16#80# .. 16#BF#
           or else (B1 = 16#F0# and then B2 < 16#90#)
           or else (B1 = 16#F4# and then B2 > 16#8F#)
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Scalar := (B1 - 16#F0#) * 262_144
           + (B2 - 16#80#) * 4_096
           + (B3 - 16#80#) * 64 + B4 - 16#80#;
         Position := Position + 4;
         Status := SMB.Ok;
      else
         Status := SMB.Invalid_Encoding;
      end if;
   end Decode_UTF8;

   --  The lemmas below state facts about the specification's recursive
   --  functions for the proof, and do nothing; checking their contracts at
   --  run time would walk the whole input at every step, so they are
   --  ignored even where every contract is checked.
   pragma Assertion_Policy (Ghost => Ignore);

   --  One step of the specification's run from Position, where a valid
   --  sequence starts: its definition unfolded once. Proved here rather than
   --  in UTF8_To_UTF16's loop.
   procedure Lemma_Run_Step (Input : String; Position : Natural)
     with Ghost,
       Pre => Input'Length <= SMB.Maximum_Frame_Size
         and then Position < Input'Length
         and then U.Valid_UTF8_At (Input, Position),
       Post =>
         U.Valid_UTF8_Run (Input, Position) =
           U.UTF8_Length (Input, Position)
           + U.Valid_UTF8_Run
               (Input, Position + U.UTF8_Length (Input, Position))
         and then U.UTF16_Run_Size (Input, Position) =
           2 * U.UTF16_Units (U.UTF8_Scalar (Input, Position))
           + U.UTF16_Run_Size
               (Input, Position + U.UTF8_Length (Input, Position))
         and then
           (for all K in 0 .. U.UTF16_Run_Size (Input, Position) - 1 =>
              U.UTF16_Run_Byte (Input, Position, K) =
                (if K < 2 * U.UTF16_Units (U.UTF8_Scalar (Input, Position))
                 then U.UTF16_Byte (U.UTF8_Scalar (Input, Position), K)
                 else U.UTF16_Run_Byte
                   (Input, Position + U.UTF8_Length (Input, Position),
                    K - 2 * U.UTF16_Units (U.UTF8_Scalar (Input, Position)))));

   procedure Lemma_Run_Step (Input : String; Position : Natural) is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Valid_UTF8_Run);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF16_Run_Size);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF16_Run_Byte);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Is_UTF16_Run);
   begin
      null;
   end Lemma_Run_Step;

   --  Where no valid sequence starts, the run is empty.
   procedure Lemma_Run_Stop (Input : String; Position : Natural)
     with Ghost,
       Pre => Input'Length <= SMB.Maximum_Frame_Size
         and then Position <= Input'Length
         and then not U.Valid_UTF8_At (Input, Position),
       Post =>
         U.Valid_UTF8_Run (Input, Position) = 0
         and then U.UTF16_Run_Size (Input, Position) = 0;

   procedure Lemma_Run_Stop (Input : String; Position : Natural) is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Valid_UTF8_Run);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF16_Run_Size);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF16_Run_Byte);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Is_UTF16_Run);
   begin
      null;
   end Lemma_Run_Stop;

   --  Data holding the run's bytes one by one is the run in UTF-16, scalar
   --  by scalar: by induction along the run.
   procedure Lemma_Run_Bytes
     (Input : String; Position : Natural; Data : SMB.Bytes; Offset : Natural)
     with Ghost,
       Pre => Input'Length <= SMB.Maximum_Frame_Size
         and then Position <= Input'Length
         and then Data'Length <= 2 * SMB.Maximum_Frame_Size
         and then Offset <= Data'Length
         and then Data'Length - Offset = U.UTF16_Run_Size (Input, Position)
         and then
           (for all K in 0 .. U.UTF16_Run_Size (Input, Position) - 1 =>
              Data (Data'First + Offset + K) =
                U.UTF16_Run_Byte (Input, Position, K)),
       Post => U.Is_UTF16_Run (Input, Position, Data, Offset),
       Subprogram_Variant => (Decreases => Input'Length - Position);

   procedure Lemma_Run_Bytes
     (Input : String; Position : Natural; Data : SMB.Bytes; Offset : Natural)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Is_UTF16_Run);
   begin
      if U.Valid_UTF8_At (Input, Position) then
         Lemma_Run_Step (Input, Position);
         declare
            Next : constant Natural :=
              Position + U.UTF8_Length (Input, Position);
            Width : constant Natural :=
              2 * U.UTF16_Units (U.UTF8_Scalar (Input, Position));
         begin
            pragma Assert
              (for all J in 0 .. Width - 1 =>
                 Data (Data'First + Offset + J) =
                   U.UTF16_Byte (U.UTF8_Scalar (Input, Position), J));
            pragma Assert
              (for all K in 0 .. U.UTF16_Run_Size (Input, Next) - 1 =>
                 U.UTF16_Run_Byte (Input, Position, Width + K) =
                   U.UTF16_Run_Byte (Input, Next, K));
            pragma Assert
              (for all K in 0 .. U.UTF16_Run_Size (Input, Next) - 1 =>
                 Data (Data'First + (Offset + Width) + K) =
                   U.UTF16_Run_Byte (Input, Next, K));
            Lemma_Run_Bytes (Input, Next, Data, Offset + Width);
         end;
      else
         Lemma_Run_Stop (Input, Position);
      end if;
   end Lemma_Run_Bytes;

   --  One scalar's step of UTF8_To_UTF16's loop: with the scalar at Start
   --  written in UTF-16 at Before, Input up to the next sequence is part of
   --  the run and Output holds the run's first Before + Width bytes.
   procedure Lemma_Extend
     (Input : String; Start : Natural; Output : SMB.Bytes; Before : Natural)
     with Ghost,
       Pre => Input'Length <= SMB.Maximum_Frame_Size
         and then Start < Input'Length
         and then U.Valid_UTF8_At (Input, Start)
         and then Output'Length <= 2 * SMB.Maximum_Frame_Size
         and then Before <= Output'Length
         and then Output'Length - Before >=
           2 * U.UTF16_Units (U.UTF8_Scalar (Input, Start))
         and then U.Valid_UTF8_Run (Input, 0) =
           Start + U.Valid_UTF8_Run (Input, Start)
         and then U.UTF16_Run_Size (Input, 0) =
           Before + U.UTF16_Run_Size (Input, Start)
         and then
           (for all K in 0 .. Before - 1 =>
              Output (Output'First + K) = U.UTF16_Run_Byte (Input, 0, K))
         and then
           (for all K in 0 .. U.UTF16_Run_Size (Input, Start) - 1 =>
              U.UTF16_Run_Byte (Input, 0, Before + K) =
                U.UTF16_Run_Byte (Input, Start, K))
         and then
           (for all J in 0 .. 2 * U.UTF16_Units (U.UTF8_Scalar (Input, Start))
                             - 1 =>
              Output (Output'First + Before + J) =
                U.UTF16_Byte (U.UTF8_Scalar (Input, Start), J)),
       Post =>
         U.Valid_UTF8_Run (Input, 0) =
           (Start + U.UTF8_Length (Input, Start))
           + U.Valid_UTF8_Run (Input, Start + U.UTF8_Length (Input, Start))
         and then U.UTF16_Run_Size (Input, 0) =
           (Before + 2 * U.UTF16_Units (U.UTF8_Scalar (Input, Start)))
           + U.UTF16_Run_Size (Input, Start + U.UTF8_Length (Input, Start))
         and then
           (for all K in
              0 .. Before + 2 * U.UTF16_Units (U.UTF8_Scalar (Input, Start))
                   - 1 =>
              Output (Output'First + K) = U.UTF16_Run_Byte (Input, 0, K))
         and then
           (for all K in
              0 .. U.UTF16_Run_Size
                     (Input, Start + U.UTF8_Length (Input, Start)) - 1 =>
              U.UTF16_Run_Byte
                (Input, 0,
                 Before + 2 * U.UTF16_Units (U.UTF8_Scalar (Input, Start))
                 + K) =
                U.UTF16_Run_Byte
                  (Input, Start + U.UTF8_Length (Input, Start), K));

   procedure Lemma_Extend
     (Input : String; Start : Natural; Output : SMB.Bytes; Before : Natural)
   is
      Scalar : constant Natural := U.UTF8_Scalar (Input, Start);
      Width : constant Natural := 2 * U.UTF16_Units (Scalar);
   begin
      Lemma_Run_Step (Input, Start);
      pragma Assert
        (for all J in 0 .. Width - 1 =>
           U.UTF16_Run_Byte (Input, Start, J) = U.UTF16_Byte (Scalar, J));
      pragma Assert
        (for all J in 0 .. Width - 1 =>
           U.UTF16_Run_Byte (Input, 0, Before + J) =
             U.UTF16_Byte (Scalar, J));
      pragma Assert
        (for all J in 0 .. Width - 1 =>
           Output (Output'First + Before + J) =
             U.UTF16_Run_Byte (Input, 0, Before + J));
      pragma Assert
        (for all K in 0 .. Before + Width - 1 =>
           Output (Output'First + K) = U.UTF16_Run_Byte (Input, 0, K));
   end Lemma_Extend;

   --  The same for UTF16_To_UTF8: Position counts 16-bit units.
   procedure Lemma_Run16_Step (Input : SMB.Bytes; Position : Natural)
     with Ghost,
       Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
         and then Position < Input'Length / 2
         and then U.Valid_UTF16_At (Input, Position),
       Post =>
         U.Valid_UTF16_Run (Input, Position) =
           U.UTF16_Length (Input, Position)
           + U.Valid_UTF16_Run
               (Input, Position + U.UTF16_Length (Input, Position))
         and then U.UTF8_Run_Size (Input, Position) =
           U.UTF8_Size (U.UTF16_Scalar (Input, Position))
           + U.UTF8_Run_Size
               (Input, Position + U.UTF16_Length (Input, Position))
         and then
           (for all K in 0 .. U.UTF8_Run_Size (Input, Position) - 1 =>
              U.UTF8_Run_Byte (Input, Position, K) =
                (if K < U.UTF8_Size (U.UTF16_Scalar (Input, Position))
                 then U.UTF8_Byte (U.UTF16_Scalar (Input, Position), K)
                 else U.UTF8_Run_Byte
                   (Input, Position + U.UTF16_Length (Input, Position),
                    K - U.UTF8_Size (U.UTF16_Scalar (Input, Position)))));

   procedure Lemma_Run16_Step (Input : SMB.Bytes; Position : Natural) is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Valid_UTF16_Run);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF8_Run_Size);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF8_Run_Byte);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Is_UTF8_Run);
   begin
      null;
   end Lemma_Run16_Step;

   procedure Lemma_Run16_Stop (Input : SMB.Bytes; Position : Natural)
     with Ghost,
       Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
         and then Position <= Input'Length / 2
         and then not U.Valid_UTF16_At (Input, Position),
       Post =>
         U.Valid_UTF16_Run (Input, Position) = 0
         and then U.UTF8_Run_Size (Input, Position) = 0;

   procedure Lemma_Run16_Stop (Input : SMB.Bytes; Position : Natural) is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Valid_UTF16_Run);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF8_Run_Size);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.UTF8_Run_Byte);
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Is_UTF8_Run);
   begin
      null;
   end Lemma_Run16_Stop;

   procedure Lemma_Run8_Bytes
     (Input : SMB.Bytes; Position : Natural; Text : String; Offset : Natural)
     with Ghost,
       Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
         and then Position <= Input'Length / 2
         and then Text'Length <= 2 * SMB.Maximum_Frame_Size
         and then Offset <= Text'Length
         and then Text'Length - Offset = U.UTF8_Run_Size (Input, Position)
         and then
           (for all K in 0 .. U.UTF8_Run_Size (Input, Position) - 1 =>
              Character'Pos (Text (Text'First + Offset + K)) =
                U.UTF8_Run_Byte (Input, Position, K)),
       Post => U.Is_UTF8_Run (Input, Position, Text, Offset),
       Subprogram_Variant => (Decreases => Input'Length / 2 - Position);

   procedure Lemma_Run8_Bytes
     (Input : SMB.Bytes; Position : Natural; Text : String; Offset : Natural)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body",
         U.Is_UTF8_Run);
   begin
      if U.Valid_UTF16_At (Input, Position) then
         Lemma_Run16_Step (Input, Position);
         declare
            Next : constant Natural :=
              Position + U.UTF16_Length (Input, Position);
            Width : constant Natural :=
              U.UTF8_Size (U.UTF16_Scalar (Input, Position));
         begin
            pragma Assert
              (for all J in 0 .. Width - 1 =>
                 Character'Pos (Text (Text'First + Offset + J)) =
                   U.UTF8_Byte (U.UTF16_Scalar (Input, Position), J));
            pragma Assert
              (for all K in 0 .. U.UTF8_Run_Size (Input, Next) - 1 =>
                 U.UTF8_Run_Byte (Input, Position, Width + K) =
                   U.UTF8_Run_Byte (Input, Next, K));
            pragma Assert
              (for all K in 0 .. U.UTF8_Run_Size (Input, Next) - 1 =>
                 Character'Pos (Text (Text'First + (Offset + Width) + K)) =
                   U.UTF8_Run_Byte (Input, Next, K));
            Lemma_Run8_Bytes (Input, Next, Text, Offset + Width);
         end;
      else
         Lemma_Run16_Stop (Input, Position);
      end if;
   end Lemma_Run8_Bytes;

   procedure Lemma_Extend8
     (Input : SMB.Bytes; Start : Natural; Output : String; Before : Natural)
     with Ghost,
       Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
         and then Start < Input'Length / 2
         and then U.Valid_UTF16_At (Input, Start)
         and then Output'Length <= 2 * SMB.Maximum_Frame_Size
         and then Before <= Output'Length
         and then Output'Length - Before >=
           U.UTF8_Size (U.UTF16_Scalar (Input, Start))
         and then U.Valid_UTF16_Run (Input, 0) =
           Start + U.Valid_UTF16_Run (Input, Start)
         and then U.UTF8_Run_Size (Input, 0) =
           Before + U.UTF8_Run_Size (Input, Start)
         and then
           (for all K in 0 .. Before - 1 =>
              Character'Pos (Output (Output'First + K)) =
                U.UTF8_Run_Byte (Input, 0, K))
         and then
           (for all K in 0 .. U.UTF8_Run_Size (Input, Start) - 1 =>
              U.UTF8_Run_Byte (Input, 0, Before + K) =
                U.UTF8_Run_Byte (Input, Start, K))
         and then
           (for all J in 0 .. U.UTF8_Size (U.UTF16_Scalar (Input, Start)) - 1
            => Character'Pos (Output (Output'First + Before + J)) =
                 U.UTF8_Byte (U.UTF16_Scalar (Input, Start), J)),
       Post =>
         U.Valid_UTF16_Run (Input, 0) =
           (Start + U.UTF16_Length (Input, Start))
           + U.Valid_UTF16_Run (Input, Start + U.UTF16_Length (Input, Start))
         and then U.UTF8_Run_Size (Input, 0) =
           (Before + U.UTF8_Size (U.UTF16_Scalar (Input, Start)))
           + U.UTF8_Run_Size (Input, Start + U.UTF16_Length (Input, Start))
         and then
           (for all K in
              0 .. Before + U.UTF8_Size (U.UTF16_Scalar (Input, Start)) - 1 =>
              Character'Pos (Output (Output'First + K)) =
                U.UTF8_Run_Byte (Input, 0, K))
         and then
           (for all K in
              0 .. U.UTF8_Run_Size
                     (Input, Start + U.UTF16_Length (Input, Start)) - 1 =>
              U.UTF8_Run_Byte
                (Input, 0,
                 Before + U.UTF8_Size (U.UTF16_Scalar (Input, Start)) + K) =
                U.UTF8_Run_Byte
                  (Input, Start + U.UTF16_Length (Input, Start), K));

   procedure Lemma_Extend8
     (Input : SMB.Bytes; Start : Natural; Output : String; Before : Natural)
   is
      Scalar : constant Natural := U.UTF16_Scalar (Input, Start);
      Width : constant Natural := U.UTF8_Size (Scalar);
   begin
      Lemma_Run16_Step (Input, Start);
      pragma Assert
        (for all J in 0 .. Width - 1 =>
           U.UTF8_Run_Byte (Input, Start, J) = U.UTF8_Byte (Scalar, J));
      pragma Assert
        (for all J in 0 .. Width - 1 =>
           U.UTF8_Run_Byte (Input, 0, Before + J) = U.UTF8_Byte (Scalar, J));
      pragma Assert
        (for all J in 0 .. Width - 1 =>
           Character'Pos (Output (Output'First + Before + J)) =
             U.UTF8_Run_Byte (Input, 0, Before + J));
      pragma Assert
        (for all K in 0 .. Before + Width - 1 =>
           Character'Pos (Output (Output'First + K)) =
             U.UTF8_Run_Byte (Input, 0, K));
   end Lemma_Extend8;

   pragma Assertion_Policy (Ghost => Check);

   --  The units of a slice that starts at an even offset are the units of
   --  the whole array from half that offset on. Proved on its own, outside
   --  UTF8_To_UTF16's large loop context, where the provers time out.
   procedure Lemma_Slice_Units (Data : SMB.Bytes; Start, Count : Natural)
     with Ghost,
       Pre => Data'Length <= 2 * SMB.Maximum_Frame_Size
         and then Start mod 2 = 0
         and then Count in 1 .. 2
         and then Start <= Data'Length - 2 * Count,
       Post =>
         (for all Unit in 0 .. Count - 1 =>
            UTF16_Unit
              (Data (Data'First + Start .. Data'First + Start + (2 * Count - 1)),
               Unit)
            = UTF16_Unit (Data, Start / 2 + Unit));

   procedure Lemma_Slice_Units (Data : SMB.Bytes; Start, Count : Natural) is
      pragma Unreferenced (Start, Count);
   begin
      null;
   end Lemma_Slice_Units;

   --  The units just emitted for one scalar, read back as their own slice,
   --  decode to that scalar. Proved here rather than inside UTF8_To_UTF16's
   --  loop, whose context makes the provers time out.
   procedure Lemma_Emitted_Scalar (Data : SMB.Bytes; Start, Stop, Scalar : Natural)
     with Ghost,
       Pre => Data'Length <= 2 * SMB.Maximum_Frame_Size
         and then Start mod 2 = 0
         and then Start <= Stop and then Stop <= Data'Length
         and then Scalar in 1 .. 16#10FFFF#
         and then Scalar not in 16#D800# .. 16#DFFF#
         and then Stop - Start = (if Scalar <= 16#FFFF# then 2 else 4)
         and then
           (if Scalar <= 16#FFFF# then
              UTF16_Unit (Data, Start / 2) = Scalar
            else
              UTF16_Unit (Data, Start / 2) in 16#D800# .. 16#DBFF#
              and then UTF16_Unit (Data, Start / 2 + 1) in 16#DC00# .. 16#DFFF#
              and then 16#10000#
                + (UTF16_Unit (Data, Start / 2) mod 1_024) * 1_024
                + UTF16_Unit (Data, Start / 2 + 1) mod 1_024
                = Scalar),
       Post =>
         UTF16_Scalar_At (Data (Data'First + Start .. Data'First + (Stop - 1)), 0)
         = Scalar;

   procedure Lemma_Emitted_Scalar (Data : SMB.Bytes; Start, Stop, Scalar : Natural) is
      pragma Unreferenced (Scalar);
   begin
      Lemma_Slice_Units (Data, Start, (Stop - Start) / 2);
   end Lemma_Emitted_Scalar;

   procedure UTF8_To_UTF16
     (Input : String;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      --  The loop invariants are for the proof: some follow SMB.Spec.Unicode
      --  over the whole input.
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Position : Natural := 0;
      --  Store_Unit's postcondition is proved. Checking it at run time would
      --  copy Output for Output'Old on every unit.
      pragma Assertion_Policy (Post => Ignore);
      --  The postcondition says which units stay as they were, so the loop
      --  is proved from that and not from the byte stores. Proving the loop
      --  from the inlined body took over 300 seconds on the GitHub runner.
      procedure Store_Unit (Unit : Natural)
      with
        Pre =>
          Output'Length <= 2 * SMB.Maximum_Frame_Size
          and then Unit <= 16#FFFF# and then Used <= Output'Length
          and then Output'Length - Used >= 2 and then Used mod 2 = 0,
        Post =>
          Used = Used'Old + 2
          and then UTF16_Unit (Output, Used'Old / 2) = Unit
          and then
            (for all K in 0 .. Used'Old / 2 - 1 =>
               UTF16_Unit (Output, K) = UTF16_Unit (Output'Old, K))
          --  A valid unit stays valid unless it is a high surrogate whose
          --  low half was the unit this call overwrote.
          and then
            (for all K in 0 .. Used'Old / 2 - 1 =>
               (if Valid_UTF16_Unit (Output'Old, K)
                  and then
                    (K + 1 < Used'Old / 2
                     or else UTF16_Unit (Output'Old, K)
                       not in 16#D800# .. 16#DBFF#)
                then Valid_UTF16_Unit (Output, K)))
          and then
            (for all Index in Output'Range =>
               (if Index - Output'First >= Used then
                  Output (Index) = Output'Old (Index)))
          and then Output (Output'First + Used'Old) = SMB.Byte (Unit mod 256)
          and then Output (Output'First + Used'Old + 1) =
            SMB.Byte (Unit / 256)
          and then
            (for all Index in Output'Range =>
               (if Index - Output'First < Used'Old then
                  Output (Index) = Output'Old (Index)))
      is
         Previous_Used : constant Natural := Used;
      begin
         pragma Assert (2 * (Previous_Used / 2) = Previous_Used);
         pragma Assert
           (Natural (SMB.Byte (Unit mod 256))
            + 256 * Natural (SMB.Byte (Unit / 256)) = Unit);
         Output (Output'First + Used) := SMB.Byte (Unit mod 256);
         Output (Output'First + Used + 1) := SMB.Byte (Unit / 256);
         Used := Used + 2;
         pragma Assert (Used = Previous_Used + 2);
         pragma Assert
           (Natural (Output (Output'First + 2 * (Previous_Used / 2)))
              = Unit mod 256
            and then
              Natural (Output (Output'First + 2 * (Previous_Used / 2) + 1))
                = Unit / 256);
         pragma Assert
           (UTF16_Unit (Output, Previous_Used / 2) = Unit);
      end Store_Unit;
      Scalar : Natural;
      Decoded_Scalar : Natural with Ghost;
      Scalar_Output_Start : Natural with Ghost;
      Scalar_Start : Natural with Ghost;
      Decode_Status : SMB.Core_Status;
   begin
      Used := 0;
      Output := (others => 0);
      --  The exit comes after the invariants, so that at the exit the
      --  provers know them and not the whole last iteration.
      loop
         pragma Loop_Invariant (Position <= Input'Length);
         pragma Loop_Invariant (Used <= Output'Length);
         pragma Loop_Invariant (Used <= 2 * Position);
         pragma Loop_Invariant (Used mod 2 = 0);
         pragma Loop_Invariant
           (for all Index in Output'Range =>
              (if Index - Output'First >= Used then Output (Index) = 0));
         pragma Loop_Invariant ((Used = 0) = (Position = 0));
         pragma Loop_Invariant
           (if Used > 0 then
              (for all Index in 0 .. Used / 2 - 1 =>
                 Valid_UTF16_Unit (Output, Index))
              and then UTF16_Unit (Output, Used / 2 - 1)
                not in 16#D800# .. 16#DBFF#);
         --  The specification's run: Input up to Position is part of it,
         --  and Output holds its first Used bytes in UTF-16.
         pragma Loop_Invariant
           (U.Valid_UTF8_Run (Input, 0) =
              Position + U.Valid_UTF8_Run (Input, Position));
         pragma Loop_Invariant
           (U.UTF16_Run_Size (Input, 0) =
              Used + U.UTF16_Run_Size (Input, Position));
         pragma Loop_Invariant
           (for all K in 0 .. Used - 1 =>
              Output (Output'First + K) = U.UTF16_Run_Byte (Input, 0, K));
         pragma Loop_Invariant
           (for all K in 0 .. U.UTF16_Run_Size (Input, Position) - 1 =>
              U.UTF16_Run_Byte (Input, 0, Used + K) =
                U.UTF16_Run_Byte (Input, Position, K));
         pragma Loop_Variant (Increases => Position);
         exit when Position >= Input'Length;
         Scalar_Start := Position;
         Decode_UTF8 (Input, Position, Scalar, Decode_Status);
         if Decode_Status /= SMB.Ok then
            declare
               pragma Assertion_Policy (Ghost => Ignore);
            begin
               Lemma_Run_Stop (Input, Scalar_Start);
            end;
            Output := (others => 0);
            Used := 0;
            Status := Decode_Status;
            return;
         end if;
         declare
            pragma Assertion_Policy (Ghost => Ignore);
         begin
            Lemma_Run_Step (Input, Scalar_Start);
         end;
         Decoded_Scalar := Scalar;
         Scalar_Output_Start := Used;
         pragma Assert (2 * (Scalar_Output_Start / 2) = Scalar_Output_Start);
         if Scalar <= 16#FFFF# then
            if Output'Length - Used < 2 then
               pragma Assert (Output'Length < 2 * Input'Length);
               Output := (others => 0);
               Used := 0;
               Status := SMB.Invalid_Length;
               return;
            end if;
            Store_Unit (Scalar);
            pragma Assert
              (Output (Output'First + Scalar_Output_Start) =
                 U.UTF16_Byte (Decoded_Scalar, 0)
               and then Output (Output'First + Scalar_Output_Start + 1) =
                 U.UTF16_Byte (Decoded_Scalar, 1));
         else
            if Output'Length - Used < 4 then
               pragma Assert (Output'Length < 2 * Input'Length);
               Output := (others => 0);
               Used := 0;
               Status := SMB.Invalid_Length;
               return;
            end if;
            Scalar := Scalar - 16#10000#;
            Store_Unit (16#D800# + Scalar / 1_024);
            Store_Unit (16#DC00# + Scalar mod 1_024);
            pragma Assert
              (Output (Output'First + Scalar_Output_Start) =
                 U.UTF16_Byte (Decoded_Scalar, 0)
               and then Output (Output'First + Scalar_Output_Start + 1) =
                 U.UTF16_Byte (Decoded_Scalar, 1)
               and then Output (Output'First + Scalar_Output_Start + 2) =
                 U.UTF16_Byte (Decoded_Scalar, 2)
               and then Output (Output'First + Scalar_Output_Start + 3) =
                 U.UTF16_Byte (Decoded_Scalar, 3));
         end if;
         pragma Assert
           (Used = Scalar_Output_Start
            + (if Decoded_Scalar <= 16#FFFF# then 2 else 4));
         pragma Assert
           (if Decoded_Scalar <= 16#FFFF# then
              UTF16_Unit (Output, Scalar_Output_Start / 2) = Decoded_Scalar
            else
              UTF16_Unit (Output, Scalar_Output_Start / 2)
                in 16#D800# .. 16#DBFF#
              and then UTF16_Unit (Output, Scalar_Output_Start / 2 + 1)
                in 16#DC00# .. 16#DFFF#
              and then 16#10000#
                + (UTF16_Unit (Output, Scalar_Output_Start / 2) mod 1_024)
                  * 1_024
                + UTF16_Unit (Output, Scalar_Output_Start / 2 + 1) mod 1_024
                = Decoded_Scalar);
         --  The emitted units, read back on their own, give the scalar.
         Lemma_Emitted_Scalar
           (Output, Scalar_Output_Start, Used, Decoded_Scalar);
         --  Their bytes are the specification's, and the run goes on.
         declare
            pragma Assertion_Policy (Ghost => Ignore);
         begin
            Lemma_Extend (Input, Scalar_Start, Output, Scalar_Output_Start);
         end;
      end loop;
      Lemma_Valid_UTF16_Prefix (Output, Used);
      declare
         pragma Assertion_Policy (Ghost => Ignore);
      begin
         Lemma_Run_Stop (Input, Position);
         Lemma_Run_Bytes
           (Input, 0, Output (Output'First .. Output'First + (Used - 1)), 0);
      end;
      Status := SMB.Ok;
   end UTF8_To_UTF16;

   procedure UTF16_To_UTF8
     (Input : SMB.Bytes;
      Output : out String;
      Used : out Natural;
      Status : out SMB.Core_Status) is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Offset : Natural := 0;
      Scalar_Start : Natural with Ghost;
      Scalar_Output_Start : Natural with Ghost;
      Scalar : Natural;
      First : Natural;
      Second : Natural;
      function Encoded_Size (Value : Natural) return Positive is
        (if Value <= 16#7F# then 1 elsif Value <= 16#7FF# then 2
         elsif Value <= 16#FFFF# then 3 else 4);
      procedure Emit_Scalar (Value : Natural; Target : out String)
        with Pre => Value in 1 .. 16#10FFFF#
          and then Value not in 16#D800# .. 16#DFFF#
          and then Target'Length = Encoded_Size (Value),
          Post => UTF8_Scalar_At (Target, 0) = Value
            and then Target'Length = U.UTF8_Size (Value)
            and then
              (for all J in 0 .. Target'Length - 1 =>
                 Character'Pos (Target (Target'First + J)) =
                   U.UTF8_Byte (Value, J));
      procedure Emit_Scalar (Value : Natural; Target : out String) is
         Written : Natural := 0;
         procedure Emit_Byte (Byte_Value : Natural) is
            Previous_Written : constant Natural := Written;
         begin
            pragma Assert (Byte_Value <= 255 and then Written < Target'Length);
            Target (Target'First + Written) := Character'Val (Byte_Value);
            Written := Written + 1;
            pragma Assert (Written = Previous_Written + 1);
            pragma Assert (Byte_At (Target, Previous_Written) = Byte_Value);
         end Emit_Byte;
      begin
         Target := (others => Character'Val (0));
         if Value <= 16#7F# then
            Emit_Byte (Value);
         elsif Value <= 16#7FF# then
            Emit_Byte (16#C0# + Value / 64);
            Emit_Byte (16#80# + Value mod 64);
         elsif Value <= 16#FFFF# then
            Emit_Byte (16#E0# + Value / 4_096);
            Emit_Byte (16#80# + (Value / 64) mod 64);
            Emit_Byte (16#80# + Value mod 64);
         else
            Emit_Byte (16#F0# + Value / 262_144);
            Emit_Byte (16#80# + (Value / 4_096) mod 64);
            Emit_Byte (16#80# + (Value / 64) mod 64);
            Emit_Byte (16#80# + Value mod 64);
         end if;
         pragma Assert (Written = Encoded_Size (Value));
      end Emit_Scalar;
   begin
      Used := 0;
      Output := (others => Character'Val (0));
      if Input'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      while Offset < Input'Length loop
         Scalar_Start := Offset;
         First := Natural (Input (Input'First + Offset))
           + Natural (Input (Input'First + Offset + 1)) * 256;
         Offset := Offset + 2;
         pragma Assert (2 * (Scalar_Start / 2) = Scalar_Start);
         pragma Assert (First = U.Code_Unit (Input, Scalar_Start / 2));
         if First = 0 then
            pragma Assert (not Valid_UTF16_Unit (Input, Scalar_Start / 2));
            Lemma_Invalid_UTF16_Unit (Input, Scalar_Start / 2);
            pragma Assert (not U.Valid_UTF16_At (Input, Scalar_Start / 2));
            declare
               pragma Assertion_Policy (Ghost => Ignore);
            begin
               Lemma_Run16_Stop (Input, Scalar_Start / 2);
            end;
            Output := (others => Character'Val (0));
            Used := 0;
            Status := SMB.Invalid_Encoding;
            return;
         elsif First in 16#D800# .. 16#DBFF# then
            if Input'Length - Offset < 2 then
               pragma Assert (not Valid_UTF16_Unit (Input, Scalar_Start / 2));
               Lemma_Invalid_UTF16_Unit (Input, Scalar_Start / 2);
               pragma Assert (not U.Valid_UTF16_At (Input, Scalar_Start / 2));
               declare
                  pragma Assertion_Policy (Ghost => Ignore);
               begin
                  Lemma_Run16_Stop (Input, Scalar_Start / 2);
               end;
               Output := (others => Character'Val (0));
               Used := 0;
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Second := Natural (Input (Input'First + Offset))
              + Natural (Input (Input'First + Offset + 1)) * 256;
            pragma Assert
              (Second = U.Code_Unit (Input, Scalar_Start / 2 + 1));
            if Second not in 16#DC00# .. 16#DFFF# then
               pragma Assert (not Valid_UTF16_Unit (Input, Scalar_Start / 2));
               Lemma_Invalid_UTF16_Unit (Input, Scalar_Start / 2);
               pragma Assert (not U.Valid_UTF16_At (Input, Scalar_Start / 2));
               declare
                  pragma Assertion_Policy (Ghost => Ignore);
               begin
                  Lemma_Run16_Stop (Input, Scalar_Start / 2);
               end;
               Output := (others => Character'Val (0));
               Used := 0;
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Scalar := 16#10000#
              + (First - 16#D800#) * 1_024 + Second - 16#DC00#;
            Offset := Offset + 2;
         elsif First in 16#DC00# .. 16#DFFF# then
            pragma Assert (not Valid_UTF16_Unit (Input, Scalar_Start / 2));
            Lemma_Invalid_UTF16_Unit (Input, Scalar_Start / 2);
            pragma Assert (not U.Valid_UTF16_At (Input, Scalar_Start / 2));
            declare
               pragma Assertion_Policy (Ghost => Ignore);
            begin
               Lemma_Run16_Stop (Input, Scalar_Start / 2);
            end;
            Output := (others => Character'Val (0));
            Used := 0;
            Status := SMB.Invalid_Encoding;
            return;
         else
            Scalar := First;
         end if;
         pragma Assert (Scalar = UTF16_Scalar_At (Input, Scalar_Start));
         pragma Assert
           (Offset = Scalar_Start + (if Scalar > 16#FFFF# then 4 else 2));
         pragma Assert
           (Valid_UTF16_Unit (Input, Scalar_Start / 2)
            and then
              (if Scalar > 16#FFFF# then
                 Valid_UTF16_Unit (Input, Scalar_Start / 2 + 1)));
         --  In the specification's terms.
         pragma Assert
           (U.Valid_UTF16_At (Input, Scalar_Start / 2)
            and then U.UTF16_Scalar (Input, Scalar_Start / 2) = Scalar
            and then Offset =
              Scalar_Start + 2 * U.UTF16_Length (Input, Scalar_Start / 2)
            and then Encoded_Size (Scalar) = U.UTF8_Size (Scalar));
         declare
            pragma Assertion_Policy (Ghost => Ignore);
         begin
            Lemma_Run16_Step (Input, Scalar_Start / 2);
         end;
         if Encoded_Size (Scalar) > Output'Length - Used then
            pragma Assert (Output'Length < 2 * Input'Length);
            Output := (others => Character'Val (0));
            Used := 0;
            Status := SMB.Invalid_Length;
            return;
         end if;
         Scalar_Output_Start := Used;
         Emit_Scalar
           (Scalar, Output (Output'First + Used
                            .. Output'First + (Used + Encoded_Size (Scalar) - 1)));
         Used := Used + Encoded_Size (Scalar);
         declare
            pragma Assertion_Policy (Ghost => Ignore);
         begin
            Lemma_Extend8 (Input, Scalar_Start / 2, Output, Scalar_Output_Start);
         end;
         pragma Loop_Invariant (Offset <= Input'Length);
         pragma Loop_Invariant (Offset mod 2 = 0);
         pragma Loop_Invariant (Used <= Output'Length);
         pragma Loop_Invariant (Used <= 2 * Offset);
         pragma Loop_Invariant
           (for all Index in Output'Range =>
              (if Index - Output'First >= Used then
                 Output (Index) = Character'Val (0)));
         pragma Loop_Invariant ((Used = 0) = (Offset = 0));
         pragma Loop_Invariant
           (if Offset > 0 then
              (for all Index in 0 .. Offset / 2 - 1 =>
                 Valid_UTF16_Unit (Input, Index))
              and then UTF16_Unit (Input, Offset / 2 - 1)
                not in 16#D800# .. 16#DBFF#);
         --  The specification's run, as in UTF8_To_UTF16.
         pragma Loop_Invariant
           (U.Valid_UTF16_Run (Input, 0) =
              Offset / 2 + U.Valid_UTF16_Run (Input, Offset / 2));
         pragma Loop_Invariant
           (U.UTF8_Run_Size (Input, 0) =
              Used + U.UTF8_Run_Size (Input, Offset / 2));
         pragma Loop_Invariant
           (for all K in 0 .. Used - 1 =>
              Character'Pos (Output (Output'First + K)) =
                U.UTF8_Run_Byte (Input, 0, K));
         pragma Loop_Invariant
           (for all K in 0 .. U.UTF8_Run_Size (Input, Offset / 2) - 1 =>
              U.UTF8_Run_Byte (Input, 0, Used + K) =
                U.UTF8_Run_Byte (Input, Offset / 2, K));
         pragma Loop_Variant (Increases => Offset);
      end loop;
      pragma Assert (Valid_UTF16_Text (Input));
      declare
         pragma Assertion_Policy (Ghost => Ignore);
      begin
         Lemma_Run16_Stop (Input, Offset / 2);
         Lemma_Run8_Bytes
           (Input, 0, Output (Output'First .. Output'First + (Used - 1)), 0);
      end;
      Status := SMB.Ok;
   end UTF16_To_UTF8;

   procedure Validate_UTF16
     (Input : SMB.Bytes;
      Status : out SMB.Core_Status) is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Offset : Natural := 0;
      First : Natural;
      Second : Natural;
   begin
      Status := SMB.Ok;
      if Input'Length mod 2 /= 0 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      while Offset < Input'Length loop
         pragma Loop_Invariant (Offset <= Input'Length);
         pragma Loop_Invariant (Offset mod 2 = 0);
         pragma Loop_Invariant
           (if Offset > 0 then
              (for all Index in 0 .. Offset / 2 - 1 =>
                 Valid_UTF16_Unit (Input, Index))
              and then UTF16_Unit (Input, Offset / 2 - 1)
                not in 16#D800# .. 16#DBFF#);
         pragma Loop_Variant (Increases => Offset);
         First := Natural (Input (Input'First + Offset))
           + Natural (Input (Input'First + Offset + 1)) * 256;
         Offset := Offset + 2;
         if First = 0 then
            Status := SMB.Invalid_Encoding;
            return;
         elsif First in 16#D800# .. 16#DBFF# then
            if Input'Length - Offset < 2 then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Second := Natural (Input (Input'First + Offset))
              + Natural (Input (Input'First + Offset + 1)) * 256;
            if Second not in 16#DC00# .. 16#DFFF# then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Offset := Offset + 2;
         elsif First in 16#DC00# .. 16#DFFF# then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
      end loop;
   end Validate_UTF16;

   procedure Uppercase_NTLM_User
     (Input : String;
      Output : out String;
      Status : out SMB.Core_Status) is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
      Character_Code : Natural;
   begin
      Output := (others => Character'Val (0));
      if Output'Length /= Input'Length then
         Status := SMB.Invalid_Length;
         return;
      end if;
      if Input'Length > 0 then
         for Offset in 0 .. Input'Length - 1 loop
            Character_Code := Character'Pos (Input (Input'First + Offset));
            if Character_Code > 16#7F# then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if Character_Code in Character'Pos ('a') .. Character'Pos ('z') then
               Character_Code := Character_Code - 32;
            end if;
            Output (Output'First + Offset) := Character'Val (Character_Code);
            pragma Loop_Invariant
              (for all J in Input'First .. Input'First + Offset =>
                 Character'Pos (Input (J)) <= 16#7F#);
            pragma Loop_Invariant
              (for all J in 0 .. Offset =>
                 Output (Output'First + J) =
                   NTLM_Uppercase_Character (Input (Input'First + J)));
         end loop;
      end if;
      Status := SMB.Ok;
   end Uppercase_NTLM_User;

   procedure Validate_Path
     (Input : String;
      Output : out String;
      Allow_Empty : Boolean;
      Status : out SMB.Core_Status) is
      pragma Assertion_Policy (Loop_Invariant => Ignore);
   begin
      Output := (others => Character'Val (0));
      if not Lexically_Valid_Path (Input, Allow_Empty) then
         Status := SMB.Invalid_Value;
         return;
      end if;
      if Input'Length > 0 then
         for Offset in 0 .. Input'Length - 1 loop
            Output (Output'First + Offset) :=
              Normalized_Path_Character (Input (Input'First + Offset));
            pragma Loop_Invariant
              (for all J in 0 .. Offset =>
                 Output (Output'First + J) =
                   Normalized_Path_Character (Input (Input'First + J)));
         end loop;
      end if;
      Status := SMB.Ok;
   end Validate_Path;

   procedure Validate_Share
     (Input : String;
      Status : out SMB.Core_Status) is
   begin
      Status :=
        (if Lexically_Valid_Share (Input) then SMB.Ok else SMB.Invalid_Value);
   end Validate_Share;
end SMB.Core_Text;
