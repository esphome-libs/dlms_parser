# OBIS Codes Found in Test Dumps

## Meter Info

| OBIS                              | Description            | Meters                                                                       |
| --------------------------------- | ---------------------- | ---------------------------------------------------------------------------- |
| 0.0.1.0.0.255                     | Clock / datetime       | norway_han_3phase, salzburg_netz                                             |
| 0.0.17.0.0.255                    | Limiter threshold      | egd_example                                                                  |
| 0.0.25.9.0.255                    | Push setup object list | energomera                                                                   |
| 0.0.42.0.0.255                    | Logical device name    | egd_example, energomera, salzburg_netz                                       |
| 0.0.96.1.0.255                    | Meter serial number    | egd_example, energomera, iskra550, landis_gyr_zmf100, norway_han_1phase, salzburg_netz |
| 0.0.96.1.1.255                    | Meter ID               | iskra550                                                                     |
| 0.0.96.1.7.255                    | Meter firmware         | landis_gyr_zmf100, norway_han_1phase                                         |
| 0.0.96.3.10.255                   | Disconnect control     | egd_example                                                                  |
| 0.0.96.5.134.255                  | Internal status word 1 | energomera                                                                   |
| 0.0.96.5.135.255                  | Internal status word 2 | energomera                                                                   |
| 0.0.96.13.0.255                   | Message code           | egd_example                                                                  |
| 0.0.96.14.0.255                   | Current tariff         | egd_example                                                                  |
| 0.0.97.98.0.255                   | Alarm register 1       | energomera                                                                   |
| 0.0.97.98.10.255                  | Alarm filter           | energomera                                                                   |
| 0.0.99.98.4.255                   | Event log              | energomera                                                                   |
| 0.1.1.0.0.255                     | Clock (billing period) | kamstrup_omnipower                                                           |
| 0.X.96.3.10.255                   | Disconnect ctrl ch X   | egd_example (X=1..6)                                                         |
| 1.0.0.0.1.255 / 1.1.0.0.1.255     | Meter serial number    | kamstrup_omnipower                                                           |
| 1.1.0.2.129.255                   | Meter type identifier  | landis_gyr_zmf100, norway_han_1phase                                         |

## Active Power (instantaneous)

| OBIS                              | Description           | Meters                                                                                                                                    |
| --------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| 1.0.1.7.0.255  / 1.1.1.7.0.255   | Active power+ total    | egd_example, iskra550, kamstrup_omnipower, landis_gyr_e450, landis_gyr_zmf100, lgz_e450_2, norway_han_1phase, norway_han_3phase, netz_noe_p1, salzburg_netz |
| 1.0.2.7.0.255  / 1.1.2.7.0.255   | Active power- total    | egd_example, iskra550, kamstrup_omnipower, landis_gyr_e450, landis_gyr_zmf100, lgz_e450_2, norway_han_1phase, norway_han_3phase, netz_noe_p1, salzburg_netz |
| 1.0.21.7.0.255 / 1.1.21.7.0.255  | Active power+ L1       | egd_example, kamstrup_omnipower, norway_han_3phase                                                                                        |
| 1.0.22.7.0.255 / 1.1.22.7.0.255  | Active power- L1       | egd_example, kamstrup_omnipower, norway_han_3phase                                                                                        |
| 1.0.41.7.0.255 / 1.1.41.7.0.255  | Active power+ L2       | egd_example, kamstrup_omnipower, norway_han_3phase                                                                                        |
| 1.0.42.7.0.255 / 1.1.42.7.0.255  | Active power- L2       | egd_example, kamstrup_omnipower, norway_han_3phase                                                                                        |
| 1.0.61.7.0.255 / 1.1.61.7.0.255  | Active power+ L3       | egd_example, kamstrup_omnipower, norway_han_3phase                                                                                        |
| 1.0.62.7.0.255 / 1.1.62.7.0.255  | Active power- L3       | egd_example, kamstrup_omnipower, norway_han_3phase                                                                                        |

## Active Energy (cumulative)

| OBIS                              | Description            | Meters                                                                                                     |
| --------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| 1.0.1.8.0.255  / 1.1.1.8.0.255    | Active energy+ total   | egd_example, iskra550, kamstrup_omnipower, landis_gyr_e450, lgz_e450_2, norway_han_3phase, netz_noe_p1, salzburg_netz |
| 1.0.2.8.0.255  / 1.1.2.8.0.255    | Active energy- total   | egd_example, iskra550, kamstrup_omnipower, landis_gyr_e450, lgz_e450_2, norway_han_3phase, netz_noe_p1, salzburg_netz |
| 1.0.1.8.1.255                     | Active energy+ T1      | egd_example, iskra550, landis_gyr_e450, lgz_e450_2                                                         |
| 1.0.1.8.2.255                     | Active energy+ T2      | egd_example, iskra550, landis_gyr_e450, lgz_e450_2                                                         |
| 1.0.1.8.3.255                     | Active energy+ T3      | egd_example                                                                                                |
| 1.0.1.8.4.255                     | Active energy+ T4      | egd_example                                                                                                |
| 1.0.2.8.1.255                     | Active energy- T1      | iskra550, landis_gyr_e450, lgz_e450_2                                                                      |
| 1.0.2.8.2.255                     | Active energy- T2      | iskra550, landis_gyr_e450, lgz_e450_2                                                                      |
| 1.0.21.8.0.255 / 1.1.21.8.0.255   | Active energy+ L1      | kamstrup_omnipower                                                                                         |
| 1.0.22.8.0.255 / 1.1.22.8.0.255   | Active energy- L1      | kamstrup_omnipower                                                                                         |
| 1.0.41.8.0.255 / 1.1.41.8.0.255   | Active energy+ L2      | kamstrup_omnipower                                                                                         |
| 1.0.42.8.0.255 / 1.1.42.8.0.255   | Active energy- L2      | kamstrup_omnipower                                                                                         |
| 1.0.61.8.0.255 / 1.1.61.8.0.255   | Active energy+ L3      | kamstrup_omnipower                                                                                         |
| 1.0.62.8.0.255 / 1.1.62.8.0.255   | Active energy- L3      | kamstrup_omnipower                                                                                         |

## Reactive Power (instantaneous)

| OBIS                              | Description            | Meters                                                                                                    |
| --------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------- |
| 1.0.3.7.0.255  / 1.1.3.7.0.255    | Reactive power+ total  | kamstrup_omnipower, landis_gyr_e450, landis_gyr_zmf100, lgz_e450_2, norway_han_1phase, norway_han_3phase  |
| 1.0.4.7.0.255  / 1.1.4.7.0.255    | Reactive power- total  | kamstrup_omnipower, landis_gyr_e450, landis_gyr_zmf100, lgz_e450_2, norway_han_1phase, norway_han_3phase  |
| 1.0.23.7.0.255                    | Reactive power+ L1     | norway_han_3phase                                                                                         |
| 1.0.24.7.0.255                    | Reactive power- L1     | norway_han_3phase                                                                                         |
| 1.0.43.7.0.255                    | Reactive power+ L2     | norway_han_3phase                                                                                         |
| 1.0.44.7.0.255                    | Reactive power- L2     | norway_han_3phase                                                                                         |
| 1.0.63.7.0.255                    | Reactive power+ L3     | norway_han_3phase                                                                                         |
| 1.0.64.7.0.255                    | Reactive power- L3     | norway_han_3phase                                                                                         |

## Reactive Energy (cumulative)

| OBIS                              | Description            | Meters                                                                                    |
| --------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------- |
| 1.0.3.8.0.255  / 1.1.3.8.0.255    | Reactive energy+ total | kamstrup_omnipower, landis_gyr_e450, lgz_e450_2, norway_han_3phase, salzburg_netz         |
| 1.0.3.8.1.255                     | Reactive energy+ T1    | landis_gyr_e450, lgz_e450_2                                                               |
| 1.0.3.8.2.255                     | Reactive energy+ T2    | landis_gyr_e450, lgz_e450_2                                                               |
| 1.0.4.8.0.255  / 1.1.4.8.0.255    | Reactive energy- total | kamstrup_omnipower, landis_gyr_e450, lgz_e450_2, norway_han_3phase, salzburg_netz         |
| 1.0.4.8.1.255                     | Reactive energy- T1    | landis_gyr_e450, lgz_e450_2                                                               |
| 1.0.4.8.2.255                     | Reactive energy- T2    | landis_gyr_e450, lgz_e450_2                                                               |

## Voltage / Current / Power Factor

| OBIS                             | Description            | Meters                                                                                                    |
| -------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------- |
| 1.0.32.7.0.255 / 1.1.32.7.0.255  | Voltage L1             | iskra550, kamstrup_omnipower, norway_han_1phase, norway_han_3phase, netz_noe_p1, salzburg_netz            |
| 1.0.52.7.0.255 / 1.1.52.7.0.255  | Voltage L2             | iskra550, kamstrup_omnipower, norway_han_3phase, netz_noe_p1, salzburg_netz                               |
| 1.0.72.7.0.255 / 1.1.72.7.0.255  | Voltage L3             | iskra550, kamstrup_omnipower, norway_han_3phase, netz_noe_p1, salzburg_netz                               |
| 1.0.31.7.0.255 / 1.1.31.7.0.255  | Current L1             | iskra550, kamstrup_omnipower, norway_han_1phase, norway_han_3phase, netz_noe_p1, salzburg_netz            |
| 1.0.51.7.0.255 / 1.1.51.7.0.255  | Current L2             | iskra550, kamstrup_omnipower, norway_han_3phase, netz_noe_p1, salzburg_netz                               |
| 1.0.71.7.0.255 / 1.1.71.7.0.255  | Current L3             | iskra550, kamstrup_omnipower, norway_han_3phase, netz_noe_p1, salzburg_netz                               |
| 1.0.13.7.0.255 / 1.1.13.7.0.255  | Power factor total     | kamstrup_omnipower, netz_noe_p1                                                                           |
| 1.0.33.7.0.255 / 1.1.33.7.0.255  | Power factor L1        | kamstrup_omnipower                                                                                        |
| 1.0.53.7.0.255 / 1.1.53.7.0.255  | Power factor L2        | kamstrup_omnipower                                                                                        |
| 1.0.73.7.0.255 / 1.1.73.7.0.255  | Power factor L3        | kamstrup_omnipower                                                                                        |

## Notes

- Kamstrup Omnipower uses A-field `1` (channel 1) instead of `0` for all measurement OBIS codes. Both refer to the same physical quantities.
- EGD example uses COSEM attribute descriptors (U.ZPA format) with untagged class-id + OBIS + attr-id.
- Encrypted dumps (kmswest, kaifa) are not included -- OBIS codes not visible without decryption key.
- Energomera dump uses a non-standard raw format; some OBIS codes are manufacturer-specific.
- Meter name prefixes (hdlc_, mbus_, raw_) omitted from the Meters column for readability.
