with System;

package body SMB.Entropy is
   use type SMB.DWord;

   function BCryptGenRandom
     (Algorithm : System.Address;
      Buffer : System.Address;
      Length, Flags : SMB.DWord) return SMB.DWord;
   pragma Import (Stdcall, BCryptGenRandom, "BCryptGenRandom");
   pragma Linker_Options ("-lbcrypt");

   procedure Generate (Output : out SMB.Bytes) is
      Result : SMB.DWord;
   begin
      if Output'Length = 0 then
         return;
      end if;
      Result := BCryptGenRandom
        (System.Null_Address, Output (Output'First)'Address,
         SMB.DWord (Output'Length), 2);
      if Result /= 0 then
         Output := (others => 0);
         raise SMB.Authentication_Error with
           "Windows operating-system entropy source failed";
      end if;
   end Generate;
end SMB.Entropy;
