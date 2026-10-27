# GitHub publication guide

## Before the first push

1. Create a **private** GitHub repository.
2. Confirm that `.env` is absent and only `.env.example` is tracked.
3. Review `git status` for reports, logs, asset lists, database dumps, keys, and
   scanner output.
4. Enable branch protection, pull-request review, secret scanning, and
   Dependabot alerts.

## Initial repository commands

```powershell
git init
git branch -M main
git add .
git status
git commit -m "chore: prepare SecureScope v5.3.6 for review"
git remote add origin https://github.com/ORGANIZATION/REPOSITORY.git
git push -u origin main
```

Replace the remote URL with the private repository created by your company.
Do not paste a personal access token into source, `.env.example`, documentation,
or terminal screenshots.

## Recommended review rules

- Require the `SecureScope CI / test` check.
- Require at least one reviewer for `main`.
- Block force pushes and branch deletion.
- Require code-owner review later, after the organization assigns owners.
- Use issues or pull requests for accepted risks and known limitations.

