/*
 * Copyright 2025 MobShield Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.mobshield.core

/**
 * Process exit policy. Default is no termination.
 *
 * A threat ends the process only when all of these hold: `detectOnly` is false; its event reaches
 * the policy's severity; at least one of its signals reaches HIGH on its own, so weak hints that only
 * add up never terminate; and its type is in [MobShieldConfig.terminateOn].
 *
 * Termination is a deterrent, not a security boundary: code that can hook the app can also stop the
 * exit call. See `docs/termination.md`.
 */
enum class TerminationPolicy {
    /** Never terminate. */
    NONE,

    /** Terminate on a corroborated threat of severity HIGH or above. */
    EXIT_ON_BYPASS,

    /** Terminate only on a corroborated threat of severity CRITICAL. */
    EXIT_ON_CRITICAL,
}
