package SMB.Core_Clock with SPARK_Mode is
   use type SMB.QWord;

   Ticks_Per_Second : constant := 10_000_000;
   Seconds_Per_Day : constant := 86_400;

   pragma Compile_Time_Error
     (Duration'Small /= 0.000_000_001,
      "AdaSMB clock conversion requires nanosecond Duration");

   function Fraction_Ticks (Fraction : Duration) return Natural is
     (Natural (Long_Long_Integer (Fraction * 1_000_000_000) / 100))
   with
     Pre => Fraction >= 0.0 and then Fraction < 1.0,
     Post =>
       Fraction_Ticks'Result < Ticks_Per_Second
       and then Fraction_Ticks'Result * Duration'(0.000_000_1) <= Fraction
       and then Fraction <
         (Fraction_Ticks'Result + 1) * Duration'(0.000_000_1);

   function Seconds_Of_Day
     (Hour, Minute, Second : Integer; Leap_Second : Boolean) return Natural is
     (Hour * 3_600 + Minute * 60 + Second + (if Leap_Second then 1 else 0))
   with
     Pre => Hour in 0 .. 23 and then Minute in 0 .. 59
       and then Second in 0 .. 59,
     Post => Seconds_Of_Day'Result <= Seconds_Per_Day;

   function Is_Leap_Year (Year : Integer) return Boolean is
     (Year mod 4 = 0 and then (Year mod 100 /= 0 or else Year mod 400 = 0));

   function Days_In_Month (Year : Integer; Month : Integer) return Positive is
     (case Month is
         when 2 => (if Is_Leap_Year (Year) then 29 else 28),
         when 4 | 6 | 9 | 11 => 30,
         when others => 31)
   with Pre => Month in 1 .. 12;

   function Valid_Time
     (Year, Month, Day, Seconds, Ticks : Integer) return Boolean is
     (Year in 1601 .. 9999
      and then Month in 1 .. 12
      and then Day in 1 .. Days_In_Month (Year, Month)
      and then Seconds in 0 .. Seconds_Per_Day
      and then Ticks in 0 .. Ticks_Per_Second - 1);

   --  Leap days in 1601 .. Year - 1; 1601 follows a 400-year boundary.
   function Days_Before_Year (Year : Integer) return Natural is
     (365 * (Year - 1601)
      + ((Year - 1) / 4 - 400)
      - ((Year - 1) / 100 - 16)
      + ((Year - 1) / 400 - 4))
   with Pre => Year in 1601 .. 9999;

   function Days_Before_Month (Year : Integer; Month : Integer) return Natural is
     ((case Month is
          when 1 => 0, when 2 => 31, when 3 => 59, when 4 => 90,
          when 5 => 120, when 6 => 151, when 7 => 181, when 8 => 212,
          when 9 => 243, when 10 => 273, when 11 => 304, when others => 334)
      + (if Month > 2 and then Is_Leap_Year (Year) then 1 else 0))
   with Pre => Month in 1 .. 12;

   function Filetime_Value
     (Year, Month, Day, Seconds, Ticks : Integer) return Long_Long_Integer is
     ((Long_Long_Integer (Days_Before_Year (Year))
       + Long_Long_Integer (Days_Before_Month (Year, Month))
       + Long_Long_Integer (Day - 1))
      * Seconds_Per_Day * Ticks_Per_Second
      + Long_Long_Integer (Seconds) * Ticks_Per_Second
      + Long_Long_Integer (Ticks))
   with Pre => Valid_Time (Year, Month, Day, Seconds, Ticks);

   --  Seconds may be 86_400 for a UTC leap second; FILETIME represents it as
   --  the first second of the next day.
   procedure To_Filetime
     (Year, Month, Day, Seconds, Ticks : Integer;
      Value : out SMB.QWord;
      Status : out SMB.Core_Status)
   with
     Post =>
       (if Valid_Time (Year, Month, Day, Seconds, Ticks) then
          Status = SMB.Ok
          and then Filetime_Value (Year, Month, Day, Seconds, Ticks) >= 0
          and then Value =
            SMB.QWord (Filetime_Value (Year, Month, Day, Seconds, Ticks))
        else Status = SMB.Invalid_Value and then Value = 0);
end SMB.Core_Clock;
