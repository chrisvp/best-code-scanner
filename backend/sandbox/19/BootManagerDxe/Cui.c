//
// FILENAME.
//      Cui.c - SecureCore Technology(TM) Character User-Interface Functions.
//
// FUNCTIONAL DESCRIPTION.
//      This file provides a number of wrappers for the Simple Text Output low-
//      level character output routines.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#include "Meta.h"

//
// Global Variables.
//

UINTN mMaxCol =  0;
UINTN mMaxRow =  0;

//
// FUNCTION NAME.
//      GetColor - Return current output color.
//
// FUNCTIONAL DESCRIPTION.
//      Get the color of the console screen.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Color           - Points to the returned console color.
//
// WARNINGS.
//      None.
//

EFI_STATUS
GetColor (OUT UINT32 *Color)
{
  *Color = gST->ConOut->Mode->Attribute;
  return EFI_SUCCESS;
} // GetColor

//
// FUNCTION NAME.
//      SetColor - Change current output color.
//
// FUNCTIONAL DESCRIPTION.
//      Set the color of the console screen.
//
// ENTRY PARAMETERS.
//      Color           - The color of the console screen.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
SetColor (IN UINT32 Color)
{
  return gST->ConOut->SetAttribute (gST->ConOut, Color);
} // SetColor

//
// FUNCTION NAME.
//      SetPosition - Set cursor position.
//
// FUNCTIONAL DESCRIPTION.
//      Set the position of the console screen.
//
// ENTRY PARAMETERS.
//      x,y             - The left top of the dialog.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
SetPosition (
  IN UINTN x,
  IN UINTN y
  )
{

  return gST->ConOut->SetCursorPosition (gST->ConOut, x, y);

} // SetPosition

//
// FUNCTION NAME.
//      ClearScreen - ClearScreen Routine.
//
// FUNCTIONAL DESCRIPTION.
//      Clear Console Screen.
//
// ENTRY PARAMETERS.
//      BackColor       - The color of the console screen.
//
// EXIT PARAMETERS.
//      EFI_SUCCESS     - The function completed successfully
//      Other value     - Unknown error
//
// WARNINGS.
//      None.
//

EFI_STATUS
ClearScreen (IN UINT32 BackColor)
{
  EFI_STATUS Status;
  UINT32 OldColor;
  UINT32 BackGroundColor;
  UINT32 FrontColor;

  GetColor (&OldColor);

  BackGroundColor = BackColor & 0xf0;
  FrontColor = BackGroundColor >> 4;
  SetColor (EFI_TEXT_ATTR(FrontColor, BackGroundColor));
  gST->ConOut->ClearScreen (gST->ConOut);

  SetColor (OldColor);
  Status = EFI_SUCCESS;
  return  Status;

} // ClearScreen

//
// FUNCTION NAME.
//      PrintChar - Print a single character to the console.
//
// FUNCTIONAL DESCRIPTION.
//      Prints a character to the default console.
//
// ENTRY PARAMETERS.
//      Character       - Character to print.
//
// EXIT PARAMETERS.
//      Length of string printed to the console.
//
// WARNINGS.
//      None.
//

UINTN
PrintChar (IN CHAR16 Character)
{
  CHAR16 Out [2];

  Out [0] = Character;
  Out [1] = L'\0';
  gST->ConOut->OutputString (gST->ConOut, Out);
  return 1;
} // PrintChar

//
// FUNCTION NAME.
//      PrintCharAt - Print character at position.
//
// FUNCTIONAL DESCRIPTION.
//      Prints a character to the console, at the supplied cursor position
//
// ENTRY PARAMETERS.
//      Column, Row     - The cursor position to print the string at
//      Character       - Character to print.
//
// EXIT PARAMETERS.
//      Length of string printed to the console.
//
// WARNINGS.
//      None.
//

UINTN
PrintCharAt (
  IN UINTN Column,
  IN UINTN Row,
  CHAR16 Character
  )
{
  SetPosition (Column, Row);
  return PrintChar (Character);
} // PrintCharAt

//
// FUNCTION NAME.
//      ClearScreenAt - Clear specified portion of screen.
//
// FUNCTIONAL DESCRIPTION.
//      Clear Console Screen at (x, y).
//
// ENTRY PARAMETERS.
//      x1,y1           - The left top of the clear screen window.
//      x2,y2           - The right bottom of clear screen window.
//      BackColor       - The color of the console screen.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
ClearScreenAt (
  IN UINTN x1,
  IN UINTN y1,
  IN UINTN x2,
  IN UINTN y2,
  IN UINT32 BackColor
  )
{
  UINTN Col;
  UINTN Row;
  UINT32 OldColor;
  UINT32 BackGroundColor;
  UINT32 FrontColor;

  GetColor (&OldColor);

  //
  // Fill the background of the dialog.
  //

  BackGroundColor = BackColor & 0xf0;
  FrontColor = BackGroundColor >> 4;
  SetColor (EFI_TEXT_ATTR(FrontColor, BackGroundColor));

  for (Row = y1; Row <= y2; Row++) {
    for (Col = x1; Col <= x2; Col++) {
      PrintCharAt (Col, Row, BLOCKELEMENT_FULL_BLOCK);
    }
    Col = x1 + 1;
  }

  SetColor (OldColor);
  return EFI_SUCCESS;
} // ClearScreenAt
