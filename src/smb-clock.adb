with Ada.Calendar;
with Ada.Calendar.Formatting;
with SMB.Core_Clock;

package body SMB.Clock is
   function Current_Filetime return SMB.QWord is
      Year : Ada.Calendar.Year_Number;
      Month : Ada.Calendar.Month_Number;
      Day : Ada.Calendar.Day_Number;
      Hour : Ada.Calendar.Formatting.Hour_Number;
      Minute : Ada.Calendar.Formatting.Minute_Number;
      Second : Ada.Calendar.Formatting.Second_Number;
      Fraction : Ada.Calendar.Formatting.Second_Duration;
      Leap_Second : Boolean;
      Value : SMB.QWord;
      Status : SMB.Core_Status;
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
      --  adamutant:disable-next-line ConditionalExpression, EqualityOperator: Split returns a Sub_Second below 1.0
      if Fraction >= 1.0 then
         raise SMB.Authentication_Error with
           "system clock returned an invalid sub-second value";
      end if;
      SMB.Core_Clock.To_Filetime
        (Year => Year,
         Month => Month,
         Day => Day,
         Seconds => SMB.Core_Clock.Seconds_Of_Day
           (Hour, Minute, Second, Leap_Second),
         Ticks => SMB.Core_Clock.Fraction_Ticks (Fraction),
         Value => Value,
         Status => Status);
      --  adamutant:disable-next-line ConditionalExpression: Ada.Calendar years (1901 .. 2399) are all in FILETIME range
      if Status /= SMB.Ok then
         raise SMB.Authentication_Error with
           "system clock is outside FILETIME range";
      end if;
      return Value;
   end Current_Filetime;
end SMB.Clock;
