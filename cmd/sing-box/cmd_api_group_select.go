package main

import (
	"github.com/sagernet/sing-box/daemon"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var flagAPIGroupSelectUnpin bool

var commandAPIGroupSelect = &cobra.Command{
	Use:   "select <group> [outbound]",
	Short: "Select an outbound in a group (or --unpin for fallback)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagAPIGroupSelectUnpin {
			if len(args) != 1 {
				return E.New("cannot specify outbound tag with --unpin")
			}
			return runAPIGroupSelect(args[0], "")
		}
		if len(args) != 2 {
			return E.New("accepts 2 arg(s), received ", len(args))
		}
		return runAPIGroupSelect(args[0], args[1])
	},
}

func init() {
	commandAPIGroupSelect.Flags().BoolVar(&flagAPIGroupSelectUnpin, "unpin", false, "Clear manual pin on a fallback group")
	commandAPIGroup.AddCommand(commandAPIGroupSelect)
}

func runAPIGroupSelect(groupTag string, outboundTag string) error {
	clientConn, client, err := createAPIClient()
	if err != nil {
		return err
	}
	defer clientConn.Close()
	_, err = client.SelectOutbound(globalCtx, &daemon.SelectOutboundRequest{
		GroupTag:    groupTag,
		OutboundTag: outboundTag,
	})
	return err
}
