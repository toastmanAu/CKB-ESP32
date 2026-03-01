#pragma once
// ed25519-donna.h — configuration header for curve25519-donna
// Enables portable 32-bit mode (safe on Xtensa, ARM Thumb, x86)
#define ED25519_32BIT
#include "ed25519-donna-portable.h"
#include "curve25519-donna-32bit.h"
#include "curve25519-donna-helpers.h"
