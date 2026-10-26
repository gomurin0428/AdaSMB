with Ada.Calendar;
with Ada.Calendar.Formatting;

package body SMB.Clock is
   Ticks_Per_Second : constant SMB.QWord := 10_000_000;
   use type SMB.QWord;

   function Is_Leap_Year (Year : Integer) return Boolean is
     (Year mod 4 = 0 and then (Year mod 100 /= 0 or else Year mod 400 = 0));

   function Current_Filetime return SMB.QWord is
      Year : Ada.Calendar.Year_Number;
      Month : Ada.Calendar.Month_Number;
      Day : Ada.Calendar.Day_Number;
      Hour : Ada.Calendar.Formatting.Hour_Number;
      Minute : Ada.Calendar.Formatting.Minute_Number;
      Second : Ada.Calendar.Formatting.Second_Number;
      Fraction : Ada.Calendar.Formatting.Second_Duration;
      Leap_Second : Boolean;
      Days : SMB.QWord := 0;
      Seconds_In_Day : Natural;
      Seconds_From_NT_Epoch : SMB.QWord;
      Fraction_Ticks : SMB.QWord;
   begin
      Ada.Calendar.Formatting.Split
        (Date => Ada.Calendar.Clock,
         Year => Year,
         Month => Month,
         Day => Day,
         Hour => Hour,
         Minute => Minute,
         Second => Second,
         Sub_Second => Fraction,
         Leap_Second => Leap_Second,
         Time_Zone => 0);
      for Y in 1601 .. Year - 1 loop
         Days := Days + (if Is_Leap_Year (Y) then 366 else 365);
      end loop;
      for M in 1 .. Month - 1 loop
         Days := Days + (if M = 2 and then Is_Leap_Year (Year)
                         then 29
                         elsif M = 2 then 28
                         elsif M = 4 or else M = 6 or else M = 9 or else M = 11
                         then 30
                         else 31);
      end loop;
      Days := Days + SMB.QWord (Day - 1);
      Seconds_In_Day :=
        Hour * 3_600 + Minute * 60 + Second
        + (if Leap_Second then 1 else 0);
      if Days > SMB.QWord'Last / 86_400 then
         raise SMB.Authentication_Error with
           "system clock is outside FILETIME range";
      end if;
      Seconds_From_NT_Epoch := Days * 86_400;
      if SMB.QWord (Seconds_In_Day) >
        SMB.QWord'Last - Seconds_From_NT_Epoch
      then
         raise SMB.Authentication_Error with
           "system clock is outside FILETIME range";
      end if;
      Seconds_From_NT_Epoch :=
        Seconds_From_NT_Epoch + SMB.QWord (Seconds_In_Day);
      if Seconds_From_NT_Epoch > SMB.QWord'Last / Ticks_Per_Second
      then
         raise SMB.Authentication_Error with
           "system clock is outside FILETIME range";
      end if;
      Fraction_Ticks :=
        SMB.QWord (Long_Long_Integer (Fraction * 10_000_000.0));
      if Fraction_Ticks > Ticks_Per_Second - 1
        or else Fraction_Ticks >
          SMB.QWord'Last - Seconds_From_NT_Epoch * Ticks_Per_Second
      then
         raise SMB.Authentication_Error with
           "system clock is outside FILETIME range";
      end if;
      return Seconds_From_NT_Epoch * Ticks_Per_Second + Fraction_Ticks;
   end Current_Filetime;
end SMB.Clock;
