"""Data-access repositories.

Repository implementations are imported directly from their modules. Keeping
this package initializer dependency-free lets database-free tests run without
loading optional database clients.
"""
