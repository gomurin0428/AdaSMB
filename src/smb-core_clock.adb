package body SMB.Core_Clock with SPARK_Mode is
   procedure To_Filetime
     (Year, Month, Day, Seconds, Ticks : Integer;
      Value : out SMB.QWord;
      Status : out SMB.Core_Status) is
   begin
      if not Valid_Time (Year, Month, Day, Seconds, Ticks) then
         Value := 0;
         Status := SMB.Invalid_Value;
         return;
      end if;
      Value := SMB.QWord (Filetime_Value (Year, Month, Day, Seconds, Ticks));
      Status := SMB.Ok;
   end To_Filetime;
end SMB.Core_Clock;
