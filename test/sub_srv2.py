#! /usr/bin/env python

from base64 import b64encode
from bottle import route, run
from random import randint

vstr = b'vmess://eyJhZGQiOiAiZ29vZ2xlLmNvbSIsICJpZCI6ICJBQkNERUZHSC1JSktMLU1OT1BRUlNUVS1WV1hZWjAxMjM0NTYiLCAicG9ydCI6IDgwMDAsICJhaWQiOiAxLCAicHMiOiAiZ29vZ2xlIiwgIm5ldCI6ICJ3cyIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAidXRwIn0='
s = 'dm1lc3M6Ly9leUpoWkdRaU9pSjFjekV1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUozY3lJc0luQmhkR2dpT2lJaUxDSndiM0owSWpvaU5EUXpJaXdpY0hNaU9pSjFPWFZ1TFhZeUxWVlRMVXh2YzBGdVoyVnNaWE1nTVNneEtTSXNJblJzY3lJNkluUnNjeUlzSW5ZaU9qSXNJbUZwWkNJNk1Td2lkSGx3WlNJNkluVjBjQ0o5DQp2bWVzczovL2V5SmhaR1FpT2lKMWN6SXVkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjNjeUlzSW5CaGRHZ2lPaUlpTENKd2IzSjBJam9pTkRReklpd2ljSE1pT2lKMU9YVnVMWFl5TFZWVExVeHZjMEZ1WjJWc1pYTWdNaWd4S1NJc0luUnNjeUk2SW5Sc2N5SXNJbllpT2pJc0ltRnBaQ0k2TVN3aWRIbHdaU0k2SW5WMGNDSjkNCnZtZXNzOi8vZXlKaFpHUWlPaUoxY3pNdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVlZUTFV4dmMwRnVaMlZzWlhNZ015Z3hLU0lzSW5Sc2N5STZJblJzY3lJc0luWWlPaklzSW1GcFpDSTZNU3dpZEhsd1pTSTZJblYwY0NKOQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSm9hekV1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUowWTNBaUxDSndZWFJvSWpvaUlpd2ljRzl5ZENJNklqZzRPQ0lzSW5Ceklqb2lkVGwxYmkxMk1pMUlTeTFJYjI1blMyOXVaeUF4S0RFcElpd2lkR3h6SWpvaUlpd2lkaUk2TWl3aVlXbGtJam94TENKMGVYQmxJam9pYm05dVpTSjkNCnZtZXNzOi8vZXlKaFpHUWlPaUpvYXpJdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKMFkzQWlMQ0p3WVhSb0lqb2lJaXdpY0c5eWRDSTZJamc0T0NJc0luQnpJam9pZFRsMWJpMTJNaTFJU3kxSWIyNW5TMjl1WnlBeUtERXBJaXdpZEd4eklqb2lJaXdpZGlJNk1pd2lZV2xrSWpveExDSjBlWEJsSWpvaWJtOXVaU0o5DQp2bWVzczovL2V5SmhaR1FpT2lKb2F6TXVkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjBZM0FpTENKd1lYUm9Jam9pSWl3aWNHOXlkQ0k2SWpRMU5pSXNJbkJ6SWpvaWRUbDFiaTEyTWkxSVN5MUliMjVuUzI5dVp5QXpLREVwSWl3aWRHeHpJam9pSWl3aWRpSTZNaXdpWVdsa0lqb3hMQ0owZVhCbElqb2libTl1WlNKOQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSm9helF1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUowWTNBaUxDSndZWFJvSWpvaUlpd2ljRzl5ZENJNklqUTFOaUlzSW5Ceklqb2lkVGwxYmkxMk1pMUlTeTFJYjI1blMyOXVaeUEwS0RFcElpd2lkR3h6SWpvaUlpd2lkaUk2TWl3aVlXbGtJam94TENKMGVYQmxJam9pYm05dVpTSjkNCnZtZXNzOi8vZXlKaFpHUWlPaUpvYXpVdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKMFkzQWlMQ0p3WVhSb0lqb2lJaXdpY0c5eWRDSTZJalExTmlJc0luQnpJam9pZFRsMWJpMTJNaTFJU3kxSWIyNW5TMjl1WnlBMUtERXBJaXdpZEd4eklqb2lJaXdpZGlJNk1pd2lZV2xrSWpveExDSjBlWEJsSWpvaWJtOXVaU0o5DQp2bWVzczovL2V5SmhaR1FpT2lKb2F6WXVkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjBZM0FpTENKd1lYUm9Jam9pSWl3aWNHOXlkQ0k2SWpRMU5pSXNJbkJ6SWpvaWRUbDFiaTEyTWkxSVN5MUliMjVuUzI5dVp5QTJLREVwSWl3aWRHeHpJam9pSWl3aWRpSTZNaXdpWVdsa0lqb3hMQ0owZVhCbElqb2libTl1WlNKOQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSm9hemN1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUowWTNBaUxDSndZWFJvSWpvaUlpd2ljRzl5ZENJNklqYzRPU0lzSW5Ceklqb2lkVGwxYmkxMk1pMUlTeTFJYjI1blMyOXVaeUEzS0RFcElpd2lkR3h6SWpvaUlpd2lkaUk2TWl3aVlXbGtJam94TENKMGVYQmxJam9pYm05dVpTSjkNCnZtZXNzOi8vZXlKaFpHUWlPaUpvYXpndWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKMFkzQWlMQ0p3WVhSb0lqb2lJaXdpY0c5eWRDSTZJamM0T1NJc0luQnpJam9pZFRsMWJpMTJNaTFJU3kxSWIyNW5TMjl1WnlBNEtERXBJaXdpZEd4eklqb2lJaXdpZGlJNk1pd2lZV2xrSWpveExDSjBlWEJsSWpvaWJtOXVaU0o5DQp2bWVzczovL2V5SmhaR1FpT2lKb2F6a3VkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjBZM0FpTENKd1lYUm9Jam9pSWl3aWNHOXlkQ0k2SWpjNE9TSXNJbkJ6SWpvaWRUbDFiaTEyTWkxSVN5MUliMjVuUzI5dVp5QTVLREVwSWl3aWRHeHpJam9pSWl3aWRpSTZNaXdpWVdsa0lqb3hMQ0owZVhCbElqb2libTl1WlNKOQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSm9hekF1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUowWTNBaUxDSndZWFJvSWpvaUlpd2ljRzl5ZENJNklqYzRPU0lzSW5Ceklqb2lkVGwxYmkxMk1pMUlTeTFJYjI1blMyOXVaeUF3S0RFcElpd2lkR3h6SWpvaUlpd2lkaUk2TWl3aVlXbGtJam94TENKMGVYQmxJam9pYm05dVpTSjkNCnZtZXNzOi8vZXlKaFpHUWlPaUpxY0RFdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVXBRTFZSdmEzbHZJREVvTVNraUxDSjBiSE1pT2lKMGJITWlMQ0oySWpveUxDSmhhV1FpT2pFc0luUjVjR1VpT2lKMWRIQWlmUT09DQp2bWVzczovL2V5SmhaR1FpT2lKcWNESXVkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjNjeUlzSW5CaGRHZ2lPaUlpTENKd2IzSjBJam9pTkRReklpd2ljSE1pT2lKMU9YVnVMWFl5TFVwUUxWUnZhM2x2SURJb01Ta2lMQ0owYkhNaU9pSjBiSE1pTENKMklqb3lMQ0poYVdRaU9qRXNJblI1Y0dVaU9pSjFkSEFpZlE9PQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSnFjRE11ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUozY3lJc0luQmhkR2dpT2lJaUxDSndiM0owSWpvaU5EUXpJaXdpY0hNaU9pSjFPWFZ1TFhZeUxVcFFMVlJ2YTNsdklETW9NU2tpTENKMGJITWlPaUowYkhNaUxDSjJJam95TENKaGFXUWlPakVzSW5SNWNHVWlPaUoxZEhBaWZRPT0NCnZtZXNzOi8vZXlKaFpHUWlPaUpxY0RRdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVXBRTFZSdmEzbHZJRFFvTVNraUxDSjBiSE1pT2lKMGJITWlMQ0oySWpveUxDSmhhV1FpT2pFc0luUjVjR1VpT2lKMWRIQWlmUT09DQp2bWVzczovL2V5SmhaR1FpT2lKcWNEVXVkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjNjeUlzSW5CaGRHZ2lPaUlpTENKd2IzSjBJam9pTkRReklpd2ljSE1pT2lKMU9YVnVMWFl5TFVwUUxWUnZhM2x2SURVb01Ta2lMQ0owYkhNaU9pSjBiSE1pTENKMklqb3lMQ0poYVdRaU9qRXNJblI1Y0dVaU9pSjFkSEFpZlE9PQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSnFjRFl1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUozY3lJc0luQmhkR2dpT2lJaUxDSndiM0owSWpvaU5EUXpJaXdpY0hNaU9pSjFPWFZ1TFhZeUxVcFFMVlJ2YTNsdklEWW9NU2tpTENKMGJITWlPaUowYkhNaUxDSjJJam95TENKaGFXUWlPakVzSW5SNWNHVWlPaUoxZEhBaWZRPT0NCnZtZXNzOi8vZXlKaFpHUWlPaUowZHpFdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVlJYTFZSaGFYQmxhU0F4S0RFcElpd2lkR3h6SWpvaWRHeHpJaXdpZGlJNk1pd2lZV2xrSWpveExDSjBlWEJsSWpvaWRYUndJbjA9DQp2bWVzczovL2V5SmhaR1FpT2lKMGR6SXVkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjNjeUlzSW5CaGRHZ2lPaUlpTENKd2IzSjBJam9pTkRReklpd2ljSE1pT2lKMU9YVnVMWFl5TFZSWExWUmhhWEJsYVNBeUtERXBJaXdpZEd4eklqb2lkR3h6SWl3aWRpSTZNaXdpWVdsa0lqb3hMQ0owZVhCbElqb2lkWFJ3SW4wPQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSnpaekV1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUozY3lJc0luQmhkR2dpT2lJaUxDSndiM0owSWpvaU5EUXpJaXdpY0hNaU9pSjFPWFZ1TFhZeUxWTkhMVk5wYm1kaGNHOXlaU2d4S1NJc0luUnNjeUk2SW5Sc2N5SXNJbllpT2pJc0ltRnBaQ0k2TVN3aWRIbHdaU0k2SW5WMGNDSjkNCnZtZXNzOi8vZXlKaFpHUWlPaUpyY2pFdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVXRTTFZObGIzVnNLREVwSWl3aWRHeHpJam9pZEd4eklpd2lkaUk2TWl3aVlXbGtJam94TENKMGVYQmxJam9pZFhSd0luMD0NCnZtZXNzOi8vZXlKaFpHUWlPaUpwYmpFdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVWxPTFVsdVpHbGhLREVwSWl3aWRHeHpJam9pZEd4eklpd2lkaUk2TWl3aVlXbGtJam94TENKMGVYQmxJam9pZFhSd0luMD0NCnZtZXNzOi8vZXlKaFpHUWlPaUp0YnpFdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVTFQTFUxaFkyRjFLREVwSWl3aWRHeHpJam9pZEd4eklpd2lkaUk2TWl3aVlXbGtJam94TENKMGVYQmxJam9pZFhSd0luMD0NCnZtZXNzOi8vZXlKaFpHUWlPaUp0ZVRFdWRqSjFPUzUwYjNBaUxDSm9iM04wSWpvaUlpd2lhV1FpT2lKRFJVSTVRVFV4TnkxRU4wWXdMVVpHUVRBdE1rSTNPUzFFTlVKQlJUWTBNalF4TVVVaUxDSnVaWFFpT2lKM2N5SXNJbkJoZEdnaU9pSWlMQ0p3YjNKMElqb2lORFF6SWl3aWNITWlPaUoxT1hWdUxYWXlMVTFaTFUxaGJHRjVjMmxoS0RFcElpd2lkR3h6SWpvaWRHeHpJaXdpZGlJNk1pd2lZV2xrSWpveExDSjBlWEJsSWpvaWRYUndJbjA9DQp2bWVzczovL2V5SmhaR1FpT2lKMGFERXVkakoxT1M1MGIzQWlMQ0pvYjNOMElqb2lJaXdpYVdRaU9pSkRSVUk1UVRVeE55MUVOMFl3TFVaR1FUQXRNa0kzT1MxRU5VSkJSVFkwTWpReE1VVWlMQ0p1WlhRaU9pSjNjeUlzSW5CaGRHZ2lPaUlpTENKd2IzSjBJam9pTkRReklpd2ljSE1pT2lKMU9YVnVMWFl5TFZSSUxWUm9ZV2xzWVc1a0tERXBJaXdpZEd4eklqb2lkR3h6SWl3aWRpSTZNaXdpWVdsa0lqb3hMQ0owZVhCbElqb2lkWFJ3SW4wPQ0Kdm1lc3M6Ly9leUpoWkdRaU9pSnBaREV1ZGpKMU9TNTBiM0FpTENKb2IzTjBJam9pSWl3aWFXUWlPaUpEUlVJNVFUVXhOeTFFTjBZd0xVWkdRVEF0TWtJM09TMUVOVUpCUlRZME1qUXhNVVVpTENKdVpYUWlPaUozY3lJc0luQmhkR2dpT2lJaUxDSndiM0owSWpvaU5EUXpJaXdpY0hNaU9pSjFPWFZ1TFhZeUxVbEVMVWx1Wkc5dVpYTnBZU2d4S1NJc0luUnNjeUk2SW5Sc2N5SXNJbllpT2pJc0ltRnBaQ0k2TVN3aWRIbHdaU0k2SW5WMGNDSjkNCg'


def subscription_getter(count=3):
    return b64encode(b'\r\n'.join([vstr] * count))


@route('/')
def index():
    return s


@route('/count/<i>')
def count(i=None):
    i = int(i)
    return subscription_getter(count=i)


@route('/count/random')
def random():
    return subscription_getter(randint(0, 10))


increase_counter = 0


@route('/count/increase')
def count_increase():
    global increase_counter
    increase_counter += 1
    return subscription_getter(increase_counter)


@route('/count/increase/reset')
def count_increase_reset():
    global increase_counter
    increase_counter = 0


def _mute():
    import sys
    import os
    os.close(1)
    sys.stdout = open('/dev/null', 'w')
    os.close(2)
    sys.stderr = open('/dev/null', 'w')


server_process = None


def start(mute=False, port=8000):
    from multiprocessing import Process
    global server_process

    def _():
        if mute:
            _mute()
        run(port=port)

    server_process = Process(target=_)
    server_process.start()

    # wait for server ready
    import requests
    while True:
        try:
            requests.get(f'http://localhost:{port}')
        except requests.exceptions.ConnectionError:
            continue
        break


def stop():
    server_process.kill()
    server_process.join()


if __name__ == '__main__':
    run()
