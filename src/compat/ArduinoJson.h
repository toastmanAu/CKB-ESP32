#pragma once
/*
 * compat/ArduinoJson.h — Build-system shim for non-Arduino hosts
 *
 * On Arduino/PlatformIO: ArduinoJson is provided by the real library.
 * On Linux/ESP-IDF/host: either install ArduinoJson via your package
 * manager / CMakeLists, or define CKB_USE_CKB_JSON to use the built-in
 * ckb_json.h parser instead (WIP — see PORTING.md).
 *
 * Quick option for host builds:
 *   git clone https://github.com/bblanchon/ArduinoJson.git \
 *     third_party/ArduinoJson
 *   Add -Ithird_party/ArduinoJson/src to your CXXFLAGS
 *
 * Then this shim is not needed at all — ArduinoJson is header-only.
 */

#ifndef ARDUINO

/* Try to include the real ArduinoJson from the include path */
#if __has_include(<ArduinoJson.h>)
  /* Found via -I path (e.g. -Ithird_party/ArduinoJson/src) */
  #include_next <ArduinoJson.h>
#elif __has_include("ArduinoJson/ArduinoJson.h")
  #include "ArduinoJson/ArduinoJson.h"
#else
  #error "ArduinoJson not found. For host builds:\n" \
         "  git clone https://github.com/bblanchon/ArduinoJson third_party/ArduinoJson\n" \
         "  Add: -Ithird_party/ArduinoJson/src to CXXFLAGS\n" \
         "See src/compat/ArduinoJson.h for details."
#endif

#endif // !ARDUINO
