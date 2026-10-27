with Ada.Streams;

package SMB.Core_Transport with SPARK_Mode is
   use type SMB.Byte;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;

   Maximum_Wire_Size : constant := SMB.Maximum_Frame_Size + 4;

   function Bounded (Data : Ada.Streams.Stream_Element_Array) return Boolean is
     (Data'First in 1 .. Maximum_Wire_Size + 1
      and then Data'Last in 0 .. Maximum_Wire_Size);

   procedure Build_Frame
     (Packet : SMB.Bytes;
      Frame : out Ada.Streams.Stream_Element_Array;
      Status : out SMB.Core_Status)
   with Pre => Packet'Length <= SMB.Maximum_Frame_Size
       and then Frame'First in 1 .. Maximum_Wire_Size + 1
       and then Frame'Last in 0 .. Maximum_Wire_Size,
     Post =>
       (if Packet'Length < 64 or else Frame'Length /= Packet'Length + 4 then
          Status = SMB.Invalid_Length
          and then (for all I in Frame'Range => Frame (I) = 0)
        else Status = SMB.Ok
          and then Frame (Frame'First) = 0
          and then Frame (Frame'First + 1) =
            Ada.Streams.Stream_Element (Packet'Length / 65_536)
          and then Frame (Frame'First + 2) =
            Ada.Streams.Stream_Element ((Packet'Length / 256) mod 256)
          and then Frame (Frame'First + 3) =
            Ada.Streams.Stream_Element (Packet'Length mod 256)
          and then
            (for all I in 0 .. Packet'Length - 1 =>
               Frame (Frame'First + 4 + Ada.Streams.Stream_Element_Offset (I)) =
                 Ada.Streams.Stream_Element (Packet (Packet'First + I))));

   procedure Receive_Chunk
     (Chunk : Ada.Streams.Stream_Element_Array;
      Last : Ada.Streams.Stream_Element_Offset;
      Buffer : in out SMB.Bytes;
      Position : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Bounded (Chunk) and then Buffer'Length <= Maximum_Wire_Size,
     Post =>
       Status =
         (if Position'Old >= Buffer'Length then SMB.Invalid_Offset
          elsif Last not in Chunk'Range then SMB.Invalid_Length
          elsif Natural (Last - Chunk'First) + 1 >
            Buffer'Length - Position'Old
          then SMB.Invalid_Length
          else SMB.Ok)
       and then
       (if Status = SMB.Ok then
          Last in Chunk'Range
          and then Position > Position'Old
          and then Position <= Buffer'Length
          and then Position =
            Position'Old + Natural (Last - Chunk'First) + 1
          and then
            (for all I in 0 .. Position - Position'Old - 1 =>
               Buffer (Buffer'First + Position'Old + I) =
                 SMB.Byte (Chunk (Chunk'First + Ada.Streams.Stream_Element_Offset (I))))
          and then
            (for all I in Buffer'Range =>
               (if I - Buffer'First < Position'Old
                  or else I - Buffer'First >= Position
                then Buffer (I) = Buffer'Old (I)))
        else Position = Position'Old and then Buffer = Buffer'Old);

   procedure Prepare_Write
     (Data : Ada.Streams.Stream_Element_Array;
      Position : Natural;
      First : out Ada.Streams.Stream_Element_Offset;
      Status : out SMB.Core_Status)
   with Pre => Bounded (Data),
     Post =>
       (if Position < Data'Length then
          Status = SMB.Ok
          and then First in Data'Range
          and then First = Data'First + Ada.Streams.Stream_Element_Offset (Position)
        else Status = SMB.Invalid_Offset and then First = Data'First);

   procedure Advance_Write
     (Data : Ada.Streams.Stream_Element_Array;
      Last : Ada.Streams.Stream_Element_Offset;
      Position : in out Natural;
      Status : out SMB.Core_Status)
   with Pre => Bounded (Data),
     Post =>
       (Status = SMB.Invalid_Offset) = (Position'Old >= Data'Length)
       and then
       (Status = SMB.Invalid_Length) =
         (Position'Old < Data'Length
          and then
            (Last < Data'First +
               Ada.Streams.Stream_Element_Offset (Position'Old)
             or else Last > Data'Last))
       and then
       (Status = SMB.Ok) =
         (Position'Old < Data'Length
          and then Last >= Data'First +
            Ada.Streams.Stream_Element_Offset (Position'Old)
          and then Last <= Data'Last)
       and then
       (if Status = SMB.Ok then
          Position > Position'Old
          and then Position <= Data'Length
          and then Last in Data'Range
          and then Position = Natural (Last - Data'First) + 1
        else Position = Position'Old)
       and then
         (if Position'Old < Data'Length
            and then Last >= Data'First + Ada.Streams.Stream_Element_Offset (Position'Old)
            and then Last <= Data'Last
          then Status = SMB.Ok);
end SMB.Core_Transport;
