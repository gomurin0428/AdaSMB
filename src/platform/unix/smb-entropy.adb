with Ada.Exceptions;
with Ada.Streams;
with Ada.Streams.Stream_IO;

package body SMB.Entropy is
   procedure Generate (Output : out SMB.Bytes) is
      use Ada.Streams;
      use Ada.Streams.Stream_IO;
      File : File_Type;
      Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Output'Length));
      Last : Stream_Element_Offset;
   begin
      Open (File, In_File, "/dev/urandom");
      Read (File, Data, Last);
      if Last < Data'Last then
         Close (File);
         raise SMB.Authentication_Error with "operating-system entropy source failed";
      end if;
      for I in Output'Range loop
         Output (I) := SMB.Byte (Data (Data'First
           + Stream_Element_Offset (I - Output'First)));
      end loop;
      Close (File);
   exception
      when SMB.Authentication_Error =>
         raise;
      when E : others =>
         if Is_Open (File) then
            Close (File);
         end if;
         raise SMB.Authentication_Error with
           "cannot read operating-system entropy: "
           & Ada.Exceptions.Exception_Message (E);
   end Generate;

end SMB.Entropy;
