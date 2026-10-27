with Interfaces;

package SMB is
   pragma SPARK_Mode (On);

   subtype Byte is Interfaces.Unsigned_8;
   subtype Word is Interfaces.Unsigned_16;
   subtype DWord is Interfaces.Unsigned_32;
   subtype QWord is Interfaces.Unsigned_64;

   type Bytes is array (Natural range <>) of Byte;
   type Core_Status is
     (Ok,
      Invalid_Length,
      Invalid_Offset,
      Invalid_Value,
      Invalid_Encoding,
      Invalid_Protocol,
      Correlation_Error,
      Signature_Error,
      Unsupported_Feature,
      Invalid_State_Status,
      Invalid_Handle_Status,
      Resource_Limit,
      Counter_Exhausted);

   SMB2_Dialect_0210 : constant Word := 16#0210#;
   Maximum_Frame_Size : constant := 1_048_576;

   Success : constant DWord := 0;
   Status_Pending : constant DWord := 16#0000_0103#;
   Status_Unsuccessful : constant DWord := 16#C0000001#;
   Status_No_Such_File : constant DWord := 16#C000000F#;
   Status_Access_Denied : constant DWord := 16#C0000022#;
   Status_Object_Name_Not_Found : constant DWord := 16#C0000034#;
   Status_Object_Name_Collision : constant DWord := 16#C0000035#;
   Status_End_Of_File : constant DWord := 16#C0000011#;
   Status_More_Processing_Required : constant DWord := 16#C0000016#;
   Status_No_More_Files : constant DWord := 16#80000006#;

   Protocol_Error : exception;
   Authentication_Error : exception;
   Transport_Error : exception;
   Invalid_State : exception;
   NT_Status_Error : exception;
end SMB;
