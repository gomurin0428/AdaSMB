with SMB.Core_Framing;

package body SMB.Core_Transport with SPARK_Mode is
   --  GNATprove still proves these invariants; runtime prefix scans are quadratic.
   pragma Assertion_Policy (Loop_Invariant => Ignore);

   procedure Build_Frame
     (Packet : SMB.Bytes;
      Frame : out Ada.Streams.Stream_Element_Array;
      Status : out SMB.Core_Status) is
      Header : SMB.Core_Framing.Frame_Header;
   begin
      Frame := (others => 0);
      if Packet'Length < 64 or else Frame'Length /= Packet'Length + 4 then
         Status := SMB.Invalid_Length;
         return;
      end if;
      SMB.Core_Framing.Encode (Packet'Length, Header, Status);
      for I in Header'Range loop
         Frame (Frame'First + Ada.Streams.Stream_Element_Offset (I)) :=
           Ada.Streams.Stream_Element (Header (I));
         pragma Loop_Invariant
           (for all J in 0 .. I =>
              Frame (Frame'First + Ada.Streams.Stream_Element_Offset (J)) =
                Ada.Streams.Stream_Element (Header (J)));
      end loop;
      for I in 0 .. Packet'Length - 1 loop
         Frame (Frame'First + 4 + Ada.Streams.Stream_Element_Offset (I)) :=
           Ada.Streams.Stream_Element (Packet (Packet'First + I));
         pragma Loop_Invariant
           (for all J in 0 .. 3 =>
              Frame (Frame'First + Ada.Streams.Stream_Element_Offset (J)) =
                Ada.Streams.Stream_Element (Header (J)));
         pragma Loop_Invariant
           (for all J in 0 .. I =>
              Frame (Frame'First + 4 + Ada.Streams.Stream_Element_Offset (J)) =
                Ada.Streams.Stream_Element (Packet (Packet'First + J)));
      end loop;
   end Build_Frame;

   procedure Receive_Chunk
     (Chunk : Ada.Streams.Stream_Element_Array;
      Last : Ada.Streams.Stream_Element_Offset;
      Buffer : in out SMB.Bytes;
      Position : in out Natural;
      Status : out SMB.Core_Status) is
      Count : Natural;
   begin
      if Position >= Buffer'Length then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      if Last not in Chunk'Range then
         Status := SMB.Invalid_Length;
         return;
      end if;
      Count := Natural (Last - Chunk'First) + 1;
      if Count > Buffer'Length - Position then
         Status := SMB.Invalid_Length;
         return;
      end if;
      for I in 0 .. Count - 1 loop
         Buffer (Buffer'First + Position + I) :=
           SMB.Byte (Chunk (Chunk'First + Ada.Streams.Stream_Element_Offset (I)));
         pragma Loop_Invariant
           (for all J in 0 .. I =>
              Buffer (Buffer'First + Position + J) =
                SMB.Byte (Chunk (Chunk'First + Ada.Streams.Stream_Element_Offset (J))));
         pragma Loop_Invariant
           (for all J in Buffer'Range =>
              (if J - Buffer'First < Position
                 or else J - Buffer'First > Position + I
               then Buffer (J) = Buffer'Loop_Entry (J)));
      end loop;
      Position := Position + Count;
      Status := SMB.Ok;
   end Receive_Chunk;

   procedure Prepare_Write
     (Data : Ada.Streams.Stream_Element_Array;
      Position : Natural;
      First : out Ada.Streams.Stream_Element_Offset;
      Status : out SMB.Core_Status) is
   begin
      First := Data'First;
      if Position >= Data'Length then
         Status := SMB.Invalid_Offset;
         return;
      end if;
      First := Data'First + Ada.Streams.Stream_Element_Offset (Position);
      Status := SMB.Ok;
   end Prepare_Write;

   procedure Advance_Write
     (Data : Ada.Streams.Stream_Element_Array;
      Last : Ada.Streams.Stream_Element_Offset;
      Position : in out Natural;
      Status : out SMB.Core_Status) is
      First : Ada.Streams.Stream_Element_Offset;
   begin
      Prepare_Write (Data, Position, First, Status);
      if Status /= SMB.Ok then
         return;
      end if;
      if Last < First or else Last > Data'Last then
         Status := SMB.Invalid_Length;
         return;
      end if;
      --  Status is still Ok from Prepare_Write.
      Position := Natural (Last - Data'First) + 1;
   end Advance_Write;
end SMB.Core_Transport;
