# Release process

The package follows Semantic Versioning. The current development version is
declared once in `src/newbiesaif/__init__.py`; setuptools reads that value when
building the package.

1. Update `__version__` for the release: increment PATCH for compatible fixes,
   MINOR for backward-compatible features, or MAJOR for incompatible changes.
2. Run the full CI checks on the merged `main` branch.
3. Create and push an annotated tag matching the package version, for example:

   ```bash
   git switch main
   git pull --ff-only
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```

4. Create a GitHub Release from that tag and include the changelog for the
   version.
5. Installers select an exact tag and never follow a moving branch:

   ```bash
   ./install.sh v0.2.0
   ```

The installer rejects untagged version strings and refuses to replace an
existing checkout with local changes.
