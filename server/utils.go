package server

import (
	"github.com/notnil/chess"
	"strings"
)

func parseAlgebraicNotation(move *chess.Move, board *chess.Board) (string, error) {
	piece := board.Piece(move.S1()).Type().String()
	piece = strings.ToUpper(piece)
	if piece == "P" {
		piece = ""
	}

	capture := ""
	if board.Piece(move.S2()) != chess.NoPiece {
		capture = "x"
	}

	tag := ""
	if move.HasTag(chess.Check) {
		tag = "+"
	}
	if move.HasTag(chess.MoveTag(chess.Checkmate)) {
		tag = "#"
	}

	return piece + capture + move.S2().String() + tag, nil
}
