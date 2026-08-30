import * as React from "react";
import { useContext, useEffect, useState } from "react";
import {
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  Container,
  Dialog,
  DialogContent,
  DialogContentText,
  DialogTitle,
  FormControl,
  IconButton,
  MenuItem,
  Portal,
  Select,
  Snackbar,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
} from "@mui/material";
import { Trans, useTranslation } from "react-i18next";
import EditIcon from "@mui/icons-material/Edit";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutlineOutlined";
import AddIcon from "@mui/icons-material/Add";
import CloseIcon from "@mui/icons-material/Close";
import ContentCopy from "@mui/icons-material/ContentCopy";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import routes from "./routes";
import session from "../app/Session";
import accountApi, { Permission, Role } from "../app/AccountApi";
import { UnauthorizedError } from "../app/errors";
import AccountContext from "./AccountContext";
import DialogFooter from "./DialogFooter";
import { Paragraph } from "./styles";
import { copyToClipboard, formatDateTime } from "../app/utils";
import { usePrefCache } from "./PrefCache";

// Admin-only user management page (fork feature). Drives the /v1/users and
// /v1/users/access admin API (see server/server_admin.go). The API cannot set the
// "admin" role and refuses to modify/delete admins, so admin rows are read-only here.
const Users = () => {
  const { account } = useContext(AccountContext);
  const unauthorized = !session.exists() || (account && account.role !== Role.ADMIN);
  useEffect(() => {
    if (unauthorized) {
      window.location.href = routes.app;
    }
  }, [unauthorized]);
  if (unauthorized) {
    return <></>;
  }
  if (!account) {
    return (
      <Container maxWidth="md" sx={{ marginTop: 3, marginBottom: 3, textAlign: "center" }}>
        <CircularProgress />
      </Container>
    );
  }
  return (
    <Container maxWidth="md" sx={{ marginTop: 3, marginBottom: 3 }}>
      <Stack spacing={3}>
        <UsersCard />
      </Stack>
    </Container>
  );
};

const UsersCard = () => {
  const { t } = useTranslation();
  const [users, setUsers] = useState(null);
  const [error, setError] = useState("");
  const [dialogKey, setDialogKey] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);

  const reload = async () => {
    try {
      const list = await accountApi.listUsers();
      list.sort((a, b) => a.username.localeCompare(b.username));
      setUsers(list);
    } catch (e) {
      console.log(`[Users] Error loading users`, e);
      if (e instanceof UnauthorizedError) {
        await session.resetAndRedirect(routes.login);
      } else {
        setError(e.message);
      }
    }
  };

  useEffect(() => {
    reload();
  }, []);

  const handleAddClick = () => {
    setDialogKey((prev) => prev + 1);
    setDialogOpen(true);
  };

  return (
    <Card sx={{ padding: 1 }} aria-label={t("admin_users_title")}>
      <CardContent sx={{ paddingBottom: 1 }}>
        <Typography variant="h5" sx={{ marginBottom: 2 }}>
          {t("admin_users_title")}
        </Typography>
        <Paragraph>{t("admin_users_description")}</Paragraph>
        <div style={{ width: "100%", overflowX: "auto" }}>
          {users === null && (
            <Box sx={{ textAlign: "center", py: 2 }}>
              <CircularProgress />
            </Box>
          )}
          {users !== null && <UsersTable users={users} onChange={reload} onError={setError} />}
        </div>
      </CardContent>
      <CardActions>
        <Button startIcon={<AddIcon />} onClick={handleAddClick}>
          {t("admin_users_add_button")}
        </Button>
      </CardActions>
      <UserDialog key={`userDialogAdd${dialogKey}`} open={dialogOpen} onClose={() => setDialogOpen(false)} onSaved={reload} />
      <Portal>
        <Snackbar open={!!error} autoHideDuration={5000} onClose={() => setError("")} message={error} />
      </Portal>
    </Card>
  );
};

const UsersTable = ({ users, onChange, onError }) => {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(null);
  const [editUser, setEditUser] = useState(null);
  const [deleteUser, setDeleteUser] = useState(null);
  const [editKey, setEditKey] = useState(0);

  const handleEditClick = (user) => {
    setEditKey((prev) => prev + 1);
    setEditUser(user);
  };

  return (
    <Table size="small" aria-label={t("admin_users_title")}>
      <TableHead>
        <TableRow>
          <TableCell sx={{ paddingLeft: 0 }} />
          <TableCell>{t("admin_users_table_username_header")}</TableCell>
          <TableCell>{t("admin_users_table_role_header")}</TableCell>
          <TableCell>{t("admin_users_table_tier_header")}</TableCell>
          <TableCell>{t("admin_users_table_grants_header")}</TableCell>
          <TableCell />
        </TableRow>
      </TableHead>
      <TableBody>
        {users.map((user) => {
          const isAdmin = user.role === Role.ADMIN;
          const isOpen = expanded === user.username;
          const grants = user.grants || [];
          return (
            <React.Fragment key={user.username}>
              <TableRow sx={{ "& > *": { borderBottom: isOpen ? "unset" : undefined } }}>
                <TableCell sx={{ paddingLeft: 0, width: 40 }}>
                  <IconButton
                    size="small"
                    aria-label={t("admin_users_table_toggle_grants")}
                    onClick={() => setExpanded(isOpen ? null : user.username)}
                  >
                    {isOpen ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
                  </IconButton>
                </TableCell>
                <TableCell component="th" scope="row" sx={{ whiteSpace: "nowrap" }}>
                  {user.username}
                </TableCell>
                <TableCell>
                  {isAdmin ? <Chip label={t("admin_users_role_admin")} size="small" color="primary" /> : t("admin_users_role_user")}
                </TableCell>
                <TableCell>{user.tier || <em>-</em>}</TableCell>
                <TableCell>{grants.length}</TableCell>
                <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>
                  {isAdmin ? (
                    <Tooltip title={t("admin_users_cannot_edit_admin")}>
                      <span>
                        <IconButton disabled>
                          <EditIcon />
                        </IconButton>
                        <IconButton disabled>
                          <CloseIcon />
                        </IconButton>
                      </span>
                    </Tooltip>
                  ) : (
                    <>
                      <Tooltip title={t("admin_users_edit_button")}>
                        <IconButton onClick={() => handleEditClick(user)} aria-label={t("admin_users_edit_button")}>
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t("admin_users_delete_button")}>
                        <IconButton onClick={() => setDeleteUser(user)} aria-label={t("admin_users_delete_button")}>
                          <CloseIcon />
                        </IconButton>
                      </Tooltip>
                    </>
                  )}
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell sx={{ paddingBottom: 0, paddingTop: 0, paddingLeft: 0 }} colSpan={6}>
                  <Collapse in={isOpen} timeout="auto" unmountOnExit>
                    <GrantsEditor user={user} onChange={onChange} onError={onError} />
                    <TokensEditor user={user} onError={onError} />
                  </Collapse>
                </TableCell>
              </TableRow>
            </React.Fragment>
          );
        })}
      </TableBody>
      <UserDialog key={`userDialogEdit${editKey}`} open={!!editUser} user={editUser} onClose={() => setEditUser(null)} onSaved={onChange} />
      <UserDeleteDialog user={deleteUser} onClose={() => setDeleteUser(null)} onDeleted={onChange} />
    </Table>
  );
};

const GrantsEditor = ({ user, onChange, onError }) => {
  const { t } = useTranslation();
  const grants = user.grants || [];
  const [newTopic, setNewTopic] = useState("");
  const [newPermission, setNewPermission] = useState(Permission.READ_ONLY);

  const runOrError = async (fn) => {
    try {
      await fn();
      await onChange();
      return true;
    } catch (e) {
      console.log(`[Users] Grant mutation failed`, e);
      if (e instanceof UnauthorizedError) {
        await session.resetAndRedirect(routes.login);
      } else {
        onError(e.message);
      }
      return false;
    }
  };

  const handleChangePermission = (topic, permission) => runOrError(() => accountApi.allowUserAccess(user.username, topic, permission));
  const handleRemove = (topic) => runOrError(() => accountApi.resetUserAccess(user.username, topic));
  const handleAdd = async () => {
    if (!newTopic.trim()) return;
    const topic = newTopic.trim();
    const ok = await runOrError(() => accountApi.allowUserAccess(user.username, topic, newPermission));
    if (ok) {
      setNewTopic("");
    }
  };

  return (
    <Box sx={{ margin: 1 }}>
      <Typography variant="subtitle2" gutterBottom>
        {t("admin_users_grants_title")}
      </Typography>
      <Table size="small" aria-label={t("admin_users_grants_title")}>
        <TableBody>
          {grants.length === 0 && (
            <TableRow>
              <TableCell sx={{ paddingLeft: 0 }} colSpan={3}>
                <em>{t("admin_users_grants_none")}</em>
              </TableCell>
            </TableRow>
          )}
          {grants.map((grant) => (
            <TableRow key={grant.topic}>
              <TableCell sx={{ paddingLeft: 0, fontFamily: "Monospace" }}>{grant.topic}</TableCell>
              <TableCell sx={{ width: 180 }}>
                <FormControl variant="standard" fullWidth>
                  <Select value={grant.permission} onChange={(ev) => handleChangePermission(grant.topic, ev.target.value)}>
                    <MenuItem value={Permission.READ_WRITE}>{t("admin_users_permission_read_write")}</MenuItem>
                    <MenuItem value={Permission.READ_ONLY}>{t("admin_users_permission_read_only")}</MenuItem>
                    <MenuItem value={Permission.WRITE_ONLY}>{t("admin_users_permission_write_only")}</MenuItem>
                    <MenuItem value={Permission.DENY_ALL}>{t("admin_users_permission_deny_all")}</MenuItem>
                  </Select>
                </FormControl>
              </TableCell>
              <TableCell align="right" sx={{ width: 48 }}>
                <Tooltip title={t("admin_users_grants_remove")}>
                  <IconButton size="small" onClick={() => handleRemove(grant.topic)} aria-label={t("admin_users_grants_remove")}>
                    <DeleteOutlineIcon />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
          <TableRow>
            <TableCell sx={{ paddingLeft: 0 }}>
              <TextField
                variant="standard"
                fullWidth
                placeholder={t("admin_users_grants_topic_placeholder")}
                value={newTopic}
                onChange={(ev) => setNewTopic(ev.target.value)}
                onKeyDown={(ev) => ev.key === "Enter" && handleAdd()}
              />
            </TableCell>
            <TableCell sx={{ width: 180 }}>
              <FormControl variant="standard" fullWidth>
                <Select value={newPermission} onChange={(ev) => setNewPermission(ev.target.value)}>
                  <MenuItem value={Permission.READ_WRITE}>{t("admin_users_permission_read_write")}</MenuItem>
                  <MenuItem value={Permission.READ_ONLY}>{t("admin_users_permission_read_only")}</MenuItem>
                  <MenuItem value={Permission.WRITE_ONLY}>{t("admin_users_permission_write_only")}</MenuItem>
                  <MenuItem value={Permission.DENY_ALL}>{t("admin_users_permission_deny_all")}</MenuItem>
                </Select>
              </FormControl>
            </TableCell>
            <TableCell align="right" sx={{ width: 48 }}>
              <Tooltip title={t("admin_users_grants_add")}>
                <span>
                  <IconButton size="small" onClick={handleAdd} disabled={!newTopic.trim()} aria-label={t("admin_users_grants_add")}>
                    <AddIcon />
                  </IconButton>
                </span>
              </Tooltip>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </Box>
  );
};

const TokensEditor = ({ user, onError }) => {
  const { t } = useTranslation();
  const { dateFormat, timeFormat } = usePrefCache();
  const [tokens, setTokens] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogKey, setDialogKey] = useState(0);
  const [snackOpen, setSnackOpen] = useState(false);

  const reload = async () => {
    try {
      setTokens(await accountApi.listUserTokens(user.username));
    } catch (e) {
      console.log(`[Users] Error loading tokens`, e);
      if (e instanceof UnauthorizedError) {
        await session.resetAndRedirect(routes.login);
      } else {
        onError(e.message);
      }
    }
  };

  useEffect(() => {
    reload();
  }, []);

  const handleCopy = (token) => {
    copyToClipboard(token);
    setSnackOpen(true);
  };

  const handleDelete = async (token) => {
    try {
      await accountApi.deleteUserToken(user.username, token);
      await reload();
    } catch (e) {
      console.log(`[Users] Error deleting token`, e);
      if (e instanceof UnauthorizedError) {
        await session.resetAndRedirect(routes.login);
      } else {
        onError(e.message);
      }
    }
  };

  const list = tokens || [];

  return (
    <Box sx={{ margin: 1, mb: 2 }}>
      <Typography variant="subtitle2" gutterBottom>
        {t("admin_users_tokens_title")}
      </Typography>
      <Table size="small" aria-label={t("admin_users_tokens_title")}>
        <TableBody>
          {list.length === 0 && (
            <TableRow>
              <TableCell sx={{ paddingLeft: 0 }} colSpan={4}>
                <em>{t("admin_users_tokens_none")}</em>
              </TableCell>
            </TableRow>
          )}
          {list.map((token) => (
            <TableRow key={token.token}>
              <TableCell sx={{ paddingLeft: 0, whiteSpace: "nowrap" }}>
                <span style={{ fontFamily: "Monospace", fontSize: "0.9rem" }}>{token.token.slice(0, 12)}</span>…
                <Tooltip title={t("admin_users_tokens_copy")} placement="right">
                  <IconButton size="small" onClick={() => handleCopy(token.token)} aria-label={t("admin_users_tokens_copy")}>
                    <ContentCopy fontSize="inherit" />
                  </IconButton>
                </Tooltip>
              </TableCell>
              <TableCell>{token.label || "-"}</TableCell>
              <TableCell sx={{ whiteSpace: "nowrap" }}>
                {token.expires ? formatDateTime(token.expires, dateFormat, timeFormat) : <em>{t("admin_users_tokens_never_expires")}</em>}
              </TableCell>
              <TableCell align="right" sx={{ width: 48 }}>
                {token.provisioned ? (
                  <Tooltip title={t("admin_users_tokens_provisioned")}>
                    <span>
                      <IconButton size="small" disabled>
                        <DeleteOutlineIcon fontSize="inherit" />
                      </IconButton>
                    </span>
                  </Tooltip>
                ) : (
                  <Tooltip title={t("admin_users_tokens_delete")}>
                    <IconButton size="small" onClick={() => handleDelete(token.token)} aria-label={t("admin_users_tokens_delete")}>
                      <DeleteOutlineIcon fontSize="inherit" />
                    </IconButton>
                  </Tooltip>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Button
        size="small"
        startIcon={<AddIcon />}
        onClick={() => {
          setDialogKey((prev) => prev + 1);
          setDialogOpen(true);
        }}
      >
        {t("admin_users_tokens_create")}
      </Button>
      <TokenCreateDialog
        key={`userTokenCreate${dialogKey}`}
        open={dialogOpen}
        username={user.username}
        onClose={() => setDialogOpen(false)}
        onCreated={reload}
        onError={onError}
      />
      <Portal>
        <Snackbar open={snackOpen} autoHideDuration={3000} onClose={() => setSnackOpen(false)} message={t("admin_users_tokens_copied")} />
      </Portal>
    </Box>
  );
};

const TokenCreateDialog = (props) => {
  const theme = useTheme();
  const { t } = useTranslation();
  const [error, setError] = useState("");
  const [label, setLabel] = useState("");
  const [expires, setExpires] = useState(0); // 0 = never expires (long-lived), suitable for an app
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));

  const handleSubmit = async () => {
    try {
      await accountApi.createUserToken(props.username, label, expires);
      await props.onCreated();
      props.onClose();
    } catch (e) {
      console.log(`[Users] Error creating token`, e);
      if (e instanceof UnauthorizedError) {
        await session.resetAndRedirect(routes.login);
      } else {
        setError(e.message);
      }
    }
  };

  return (
    <Dialog open={props.open} onClose={props.onClose} maxWidth="sm" fullWidth fullScreen={fullScreen}>
      <DialogTitle>{t("admin_users_tokens_dialog_title", { username: props.username })}</DialogTitle>
      <DialogContent>
        <TextField
          autoFocus
          margin="dense"
          label={t("admin_users_tokens_dialog_label")}
          type="text"
          value={label}
          onChange={(ev) => setLabel(ev.target.value)}
          fullWidth
          variant="standard"
        />
        <FormControl fullWidth variant="standard" sx={{ mt: 1 }}>
          <Select value={expires} onChange={(ev) => setExpires(ev.target.value)} aria-label={t("admin_users_tokens_dialog_expires")}>
            <MenuItem value={0}>{t("admin_users_tokens_dialog_expires_never")}</MenuItem>
            <MenuItem value={2592000}>{t("admin_users_tokens_dialog_expires_x_days", { days: 30 })}</MenuItem>
            <MenuItem value={7776000}>{t("admin_users_tokens_dialog_expires_x_days", { days: 90 })}</MenuItem>
            <MenuItem value={15552000}>{t("admin_users_tokens_dialog_expires_x_days", { days: 180 })}</MenuItem>
          </Select>
        </FormControl>
      </DialogContent>
      <DialogFooter status={error}>
        <Button onClick={props.onClose}>{t("admin_users_dialog_button_cancel")}</Button>
        <Button onClick={handleSubmit}>{t("admin_users_tokens_dialog_button_create")}</Button>
      </DialogFooter>
    </Dialog>
  );
};

const UserDialog = (props) => {
  const theme = useTheme();
  const { t } = useTranslation();
  const editMode = !!props.user;
  const [error, setError] = useState("");
  const [username, setUsername] = useState(props.user?.username || "");
  const [password, setPassword] = useState("");
  const [tier, setTier] = useState(props.user?.tier || "");
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));

  // In edit mode the API needs a new password or a non-empty changed tier (the server ignores an
  // empty tier, so clearing it is a no-op and must not enable Save); in add mode username + password.
  const tierChanged = tier !== "" && tier !== (props.user?.tier || "");
  const submitDisabled = editMode ? password === "" && !tierChanged : username.trim() === "" || password === "";

  const handleSubmit = async () => {
    try {
      if (editMode) {
        await accountApi.updateUser(props.user.username, password, tier);
      } else {
        await accountApi.addUser(username.trim(), password, tier);
      }
      await props.onSaved();
      props.onClose();
    } catch (e) {
      console.log(`[Users] Error saving user`, e);
      if (e instanceof UnauthorizedError) {
        await session.resetAndRedirect(routes.login);
      } else {
        setError(e.message);
      }
    }
  };

  return (
    <Dialog open={props.open} onClose={props.onClose} maxWidth="sm" fullWidth fullScreen={fullScreen}>
      <DialogTitle>
        {editMode ? t("admin_users_dialog_title_edit", { username: props.user?.username }) : t("admin_users_dialog_title_add")}
      </DialogTitle>
      <DialogContent>
        {!editMode && (
          <TextField
            autoFocus
            margin="dense"
            label={t("admin_users_dialog_username_label")}
            type="text"
            value={username}
            onChange={(ev) => setUsername(ev.target.value)}
            fullWidth
            variant="standard"
          />
        )}
        <TextField
          margin="dense"
          label={editMode ? t("admin_users_dialog_password_label_edit") : t("admin_users_dialog_password_label")}
          type="password"
          value={password}
          onChange={(ev) => setPassword(ev.target.value)}
          fullWidth
          variant="standard"
        />
        <TextField
          margin="dense"
          label={t("admin_users_dialog_tier_label")}
          type="text"
          value={tier}
          onChange={(ev) => setTier(ev.target.value)}
          fullWidth
          variant="standard"
        />
      </DialogContent>
      <DialogFooter status={error}>
        <Button onClick={props.onClose}>{t("admin_users_dialog_button_cancel")}</Button>
        <Button onClick={handleSubmit} disabled={submitDisabled}>
          {editMode ? t("admin_users_dialog_button_save") : t("admin_users_dialog_button_add")}
        </Button>
      </DialogFooter>
    </Dialog>
  );
};

const UserDeleteDialog = (props) => {
  const { t } = useTranslation();
  const [error, setError] = useState("");

  const handleSubmit = async () => {
    try {
      await accountApi.deleteUser(props.user.username);
      await props.onDeleted();
      props.onClose();
    } catch (e) {
      console.log(`[Users] Error deleting user`, e);
      if (e instanceof UnauthorizedError) {
        await session.resetAndRedirect(routes.login);
      } else {
        setError(e.message);
      }
    }
  };

  return (
    <Dialog open={!!props.user} onClose={props.onClose}>
      <DialogTitle>{t("admin_users_delete_dialog_title")}</DialogTitle>
      <DialogContent>
        <DialogContentText>
          <Trans i18nKey="admin_users_delete_dialog_description" values={{ username: props.user?.username }} />
        </DialogContentText>
      </DialogContent>
      <DialogFooter status={error}>
        <Button onClick={props.onClose}>{t("admin_users_dialog_button_cancel")}</Button>
        <Button onClick={handleSubmit} color="error">
          {t("admin_users_delete_dialog_submit_button")}
        </Button>
      </DialogFooter>
    </Dialog>
  );
};

export default Users;
