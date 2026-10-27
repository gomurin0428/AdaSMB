with Ada.Text_IO;
with SMB.Core_Clock;

procedure Clock_Probe is
   use type SMB.Core_Status;
   use type SMB.QWord;

   Buffer : String (1 .. 256);
   Last : Natural;
   Count : Natural := 0;
begin
   while not Ada.Text_IO.End_Of_File loop
      Ada.Text_IO.Get_Line (Buffer, Last);
      declare
         Line : String renames Buffer (1 .. Last);
         Spaces : array (0 .. 8) of Natural := (others => 0);
         Space_Count : Natural := 0;

         function Field (Index : Positive) return String is
         begin
            if Index > Space_Count + 1 then
               raise Program_Error with "missing clock fixture field";
            end if;
            return Line (Spaces (Index - 1) + 1 .. Spaces (Index) - 1);
         end Field;
      begin
         for I in Line'Range loop
            if Line (I) = ' ' then
               if Space_Count = 7 then
                  raise Program_Error with "too many clock fixture fields";
               end if;
               Space_Count := Space_Count + 1;
               Spaces (Space_Count) := I;
            end if;
         end loop;
         Spaces (Space_Count + 1) := Last + 1;
         if Field (1) = "T" and then Space_Count = 7 then
            declare
               Value : SMB.QWord := SMB.QWord'Last;
               Status : SMB.Core_Status := SMB.Ok;
            begin
               SMB.Core_Clock.To_Filetime
                 (Integer'Value (Field (2)), Integer'Value (Field (3)),
                  Integer'Value (Field (4)), Integer'Value (Field (5)),
                  Integer'Value (Field (6)), Value, Status);
               if Value /= SMB.QWord'Value (Field (7))
                 or else Status /= SMB.Core_Status'Value (Field (8))
               then
                  raise Program_Error with "FILETIME mismatch";
               end if;
            end;
         elsif Field (1) = "S" and then Space_Count = 5 then
            if SMB.Core_Clock.Seconds_Of_Day
              (Integer'Value (Field (2)), Integer'Value (Field (3)),
               Integer'Value (Field (4)), Boolean'Value (Field (5)))
              /= Natural'Value (Field (6))
            then
               raise Program_Error with "seconds mismatch";
            end if;
         elsif Field (1) = "F" and then Space_Count = 2 then
            if SMB.Core_Clock.Fraction_Ticks (Duration'Value (Field (2)))
              /= Natural'Value (Field (3))
            then
               raise Program_Error with "fraction mismatch";
            end if;
         else
            raise Program_Error with "invalid clock fixture operation";
         end if;
         Count := Count + 1;
      end;
   end loop;
   Ada.Text_IO.Put_Line ("PASS" & Natural'Image (Count));
exception
   when others =>
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error, "FAIL" & Natural'Image (Count + 1));
      raise;
end Clock_Probe;
