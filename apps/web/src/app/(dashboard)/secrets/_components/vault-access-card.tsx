"use client";

import { useState } from "react";
import { Shield, Unlink, Link, Fingerprint } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@onecli/ui/components/alert-dialog";
import { Badge } from "@onecli/ui/components/badge";
import { Button } from "@onecli/ui/components/button";
import { Input } from "@onecli/ui/components/input";
import { Label } from "@onecli/ui/components/label";
import { Separator } from "@onecli/ui/components/separator";
import { Skeleton } from "@onecli/ui/components/skeleton";
import {
  useVaultStatus,
  useVaultPair,
  useVaultDisconnect,
  type BitwardenStatusData,
} from "@/hooks/use-vault-status";

export const VaultAccessCard = () => {
  const { status, loading, isPaired, isReady, fetchStatus } =
    useVaultStatus<BitwardenStatusData>();
  const { pair, pairing } = useVaultPair(fetchStatus);
  const { disconnect, disconnecting } = useVaultDisconnect(fetchStatus);
  const [pairingCode, setPairingCode] = useState("");

  const isValidCode =
    pairingCode.includes("_") &&
    pairingCode.split("_").length === 2 &&
    pairingCode.split("_").every((part) => part.length === 64);

  const handlePair = async () => {
    const parts = pairingCode.split("_");
    const success = await pair(parts[0]!, parts[1]!);
    if (success) {
      setPairingCode("");
    }
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-36" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-24" />
        </CardContent>
      </Card>
    );
  }

  if (isPaired) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="text-muted-foreground size-4" />
              <CardTitle>Bitwarden Vault</CardTitle>
            </div>
            <Badge
              variant="outline"
              className={
                isReady
                  ? "border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400"
                  : "border-yellow-200 bg-yellow-50 text-yellow-700 dark:border-yellow-800 dark:bg-yellow-950 dark:text-yellow-400"
              }
            >
              <span
                className={`mr-1.5 inline-block size-1.5 rounded-full ${isReady ? "bg-green-500" : "bg-yellow-500 animate-pulse"}`}
              />
              {isReady ? "Connected" : "Reconnecting"}
            </Badge>
          </div>
          <CardDescription>
            Credentials will be fetched on-demand when no matching local secrets
            are configured.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {status?.status_data?.fingerprint && (
            <div className="grid gap-1.5">
              <Label className="flex items-center gap-1.5">
                <Fingerprint className="size-3.5" />
                Device Fingerprint
              </Label>
              <code className="text-muted-foreground text-xs font-mono break-all">
                {status.status_data.fingerprint}
              </code>
            </div>
          )}

          <Separator />

          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" className="w-fit" size="sm">
                <Unlink className="size-3.5" />
                Disconnect
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Disconnect vault?</AlertDialogTitle>
                <AlertDialogDescription>
                  This will remove the pairing with your Bitwarden vault.
                  Credentials will no longer be fetched on-demand. You can
                  reconnect at any time.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  variant="destructive"
                  onClick={disconnect}
                  disabled={disconnecting}
                >
                  {disconnecting ? "Disconnecting..." : "Disconnect"}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Shield className="text-muted-foreground size-4" />
          <CardTitle>Bitwarden Vault</CardTitle>
        </div>
        <CardDescription>
          Connect your Bitwarden vault to inject credentials on-demand without
          storing them on the server. Run{" "}
          <code className="text-xs">aac listen --psk</code> to generate a
          pairing code.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-2">
          <Label htmlFor="pairing-code">Pairing Code</Label>
          <Input
            id="pairing-code"
            value={pairingCode}
            onChange={(e) => setPairingCode(e.target.value)}
            placeholder="a1b2c3d4..._e5f6a7b8..."
            className="font-mono text-sm"
          />
          <p className="text-muted-foreground text-xs">
            Paste the pairing code from{" "}
            <code className="text-xs">aac listen --psk</code>.
          </p>
        </div>
        <Button
          onClick={handlePair}
          loading={pairing}
          disabled={!isValidCode}
          className="w-fit"
        >
          <Link className="size-3.5" />
          {pairing ? "Connecting..." : "Connect Vault"}
        </Button>
      </CardContent>
    </Card>
  );
};
