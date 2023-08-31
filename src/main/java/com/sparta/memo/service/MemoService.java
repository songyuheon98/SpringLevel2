package com.sparta.memo.service;

import com.sparta.memo.dto.MemoRequestDto;
import com.sparta.memo.dto.MemoResponseDto;
import com.sparta.memo.entity.Memo;
import com.sparta.memo.repository.MemoRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service// 빈으로 등록
public class MemoService {

    private final MemoRepository memoRepository; // final은 무조건 생성자로 주입
    public MemoService(MemoRepository memoRepository) {
        this.memoRepository = memoRepository;
    }



    public MemoResponseDto createMemo(MemoRequestDto requestDto, String username) {
        // RequestDto -> Entity
        Memo memo = new Memo(requestDto);

        // DB 저장
        Memo saveMemo = memoRepository.save(memo);

        // Entity -> ResponseDto
        MemoResponseDto memoResponseDto = new MemoResponseDto(saveMemo);

        return memoResponseDto;
    }

    public List<MemoResponseDto> getMemos() {
        // DB 조회
        return memoRepository.findAllByOrderByCreatedAtDesc().stream().map(MemoResponseDto::fromMemo).toList();// 메모를 리스트 타입으로 반환
    }

    public MemoResponseDto getOneMemo(Long id) {
        // DB 조회
        Memo memo = memoRepository.findMemoById(id);

        return MemoResponseDto.fromMemo(memo);
    }

    @Transactional // updateMemo는 따로 Transactional 되어있지 않아 해줘야함
    public Memo updateMemo(Long id, MemoRequestDto requestDto, String username) {
        Memo memo = findMemo(id);
        if(memo.getUsername().equals(username))
            memo.update(requestDto, username); // update는 memo 클래스에서 만든 것
        else
            throw new IllegalArgumentException("당신에겐 글을 수정할 권한이 없습니다 >.< !!");

        return memo;
    }

    public ResponseEntity<String>  deleteMemo(Long id, String username) {
        Memo memo = findMemo(id);
        if(memo.getUsername().equals(username))
            memoRepository.delete(memo);
        else
            return ResponseEntity.ok("{\"msg\": \"삭제 실패\", \"statusCode\": 444}");
        return ResponseEntity.ok("{\"msg\": \"삭제 성공\", \"statusCode\": 200}");

    }

    private Memo findMemo(Long id) { // 메모 찾기
        return memoRepository.findById(id).orElseThrow(() ->  // null 시 오류 메시지 출력
                new IllegalArgumentException("선택한 메모는 존재하지 않습니다.")
        );
    }



}