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

	return piece + capture + move.S2().String(), nil
}
